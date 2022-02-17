from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from flask import Blueprint, url_for
from saml2 import BINDING_HTTP_POST

from eduid.userdb import LockedIdentityNin
from eduid.userdb.credentials import FidoCredential, Password
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.messages import FluxData, error_response, success_response
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import RequestRef
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.helpers import IdPAction, IdPMsg
from eduid.webapp.idp.idp_saml import cancel_saml_request
from eduid.webapp.idp.login import SSO, get_ticket, login_next_step
from eduid.webapp.idp.login_context import LoginContext, LoginContextOtherDevice, LoginContextSAML
from eduid.webapp.idp.other_device.device2 import device2_finish
from eduid.webapp.idp.schemas import NextRequestSchema, NextResponseSchema
from eduid.webapp.idp.service import SAMLQueryParams
from eduid.webapp.idp.sso_session import SSOSession

next_views = Blueprint('next', __name__, url_prefix='')


@next_views.route('/next', methods=['POST'])
@UnmarshalWith(NextRequestSchema)
@MarshalWith(NextResponseSchema)
def next_view(ref: RequestRef) -> FluxData:
    """ Main state machine for frontend """
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- Next ({ref}) ---')

    if not current_app.conf.login_bundle_url:
        return error_response(message=IdPMsg.not_available)

    _info = SAMLQueryParams(request_ref=ref)
    ticket = get_ticket(_info, None)
    if not ticket:
        _pending = session.idp.pending_requests
        current_app.logger.debug(f'Login ref {ref} not found in pending_requests: {_pending.keys()}')
        return error_response(message=IdPMsg.bad_ref)

    sso_session = current_app._lookup_sso_session()

    _next = login_next_step(ticket, sso_session)
    current_app.logger.debug(f'Login Next: {_next}')

    if _next.message == IdPMsg.aborted:
        if isinstance(ticket, LoginContextSAML):
            saml_params = cancel_saml_request(ticket, current_app.conf)

            if saml_params.binding != BINDING_HTTP_POST:
                current_app.logger.error(f'SAML response does not have binding HTTP_POST')
                return error_response(message=IdPMsg.general_failure)

            return success_response(
                message=IdPMsg.finished,
                payload={
                    'action': IdPAction.FINISHED.value,
                    'target': saml_params.url,
                    'parameters': saml_params.post_params,
                },
            )

        current_app.logger.error(f'Don\'t know how to abort login request {ticket}')
        return error_response(message=IdPMsg.general_failure)

    if _next.message == IdPMsg.other_device:
        _payload = {
            'action': IdPAction.OTHER_DEVICE.value,
            'target': url_for('other_device.use_other_1', _external=True),
            'authn_options': _get_authn_options(ticket, sso_session),
            'service_info': _get_service_info(ticket),
        }

        return success_response(message=IdPMsg.must_authenticate, payload=_payload,)

    if _next.message == IdPMsg.must_authenticate:
        _payload = {
            'action': IdPAction.PWAUTH.value,
            'target': url_for('pw_auth.pw_auth', _external=True),
            'authn_options': _get_authn_options(ticket, sso_session),
            'service_info': _get_service_info(ticket),
        }

        return success_response(message=IdPMsg.must_authenticate, payload=_payload,)

    if _next.message == IdPMsg.mfa_required:
        return success_response(
            message=IdPMsg.mfa_required,
            payload={
                'action': IdPAction.MFA.value,
                'target': url_for('mfa_auth.mfa_auth', _external=True),
                'authn_options': _get_authn_options(ticket, sso_session),
                'service_info': _get_service_info(ticket),
            },
        )

    if _next.message == IdPMsg.tou_required:
        return success_response(
            message=IdPMsg.tou_required,
            payload={'action': IdPAction.TOU.value, 'target': url_for('tou.tou', _external=True)},
        )

    if _next.message == IdPMsg.user_terminated:
        return error_response(message=IdPMsg.user_terminated)

    if _next.message == IdPMsg.swamid_mfa_required:
        return error_response(message=IdPMsg.swamid_mfa_required)

    if _next.message == IdPMsg.proceed:
        if not sso_session:
            return error_response(message=IdPMsg.no_sso_session)

        user = current_app.userdb.lookup_user(sso_session.eppn)
        if not user:
            current_app.logger.error(f'User with eppn {sso_session.eppn} (from SSO session) not found')
            return error_response(message=IdPMsg.general_failure)

        sso = SSO(sso_session=sso_session)
        # please mypy
        if not _next.authn_info or not _next.authn_state:
            raise RuntimeError(f'Missing expected data in next result: {_next}')

        if isinstance(ticket, LoginContextSAML):
            saml_params = sso.get_response_params(_next.authn_info, ticket, user)
            if saml_params.binding != BINDING_HTTP_POST:
                current_app.logger.error(f'SAML response does not have binding HTTP_POST')
                return error_response(message=IdPMsg.general_failure)
            return success_response(
                message=IdPMsg.finished,
                payload={
                    'action': IdPAction.FINISHED.value,
                    'target': saml_params.url,
                    'parameters': saml_params.post_params,
                },
            )
        elif isinstance(ticket, LoginContextOtherDevice):
            if not ticket.is_other_device_2:
                # We shouldn't be able to get here, but this clearly shows where this code runs
                current_app.logger.warning(f'Ticket is LoginContextOtherDevice, but this is not device #2')
                return error_response(message=IdPMsg.general_failure)

            return device2_finish(ticket, sso_session, _next.authn_state)
        current_app.logger.error(f'Don\'t know how to finish login request {ticket}')
        return error_response(message=IdPMsg.general_failure)

    return error_response(message=IdPMsg.not_implemented)


@dataclass
class AuthnOptions:
    """
    Different options regarding authentication. These might change during the course of the authentication.

    For example: after providing a username, password authentication becomes available if the user has such
    credentials.
    """

    display_name: Optional[str] = None
    # Is this login locked to being performed by a particular user? (Identified by the email/phone/...)
    forced_username: Optional[str] = None
    # Can an unknown user log in using just a Freja eID+? Yes, if there is an eduID user with the users (verified) NIN.
    freja_eidplus: bool = True
    # If the user has a session, 'logout' should be shown (to allow switch of users).
    has_session: bool = False
    # Can the user log (an unknown user) log in using another device? Sure.
    other_device: bool = True
    # Can the frontend start with just asking for a password? No, not unless we know who the user is.
    password: bool = False
    # Can an unknown user log in using a username and a password? Defaults to True.
    usernamepassword: bool = True
    # Can the frontend start with just asking for a username? Sure.
    username: bool = True
    # Can an unknown user log in using a webauthn credential? No, not at this time (might be doable).
    webauthn: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def valid_options(self) -> List[str]:
        _data = self.to_dict()
        return [x for x in _data.keys() if _data[x]]


def _get_authn_options(ticket: LoginContext, sso_session: Optional[SSOSession]) -> Dict[str, Any]:
    res = AuthnOptions()

    sp_request_eppn = None
    if isinstance(ticket, LoginContextSAML):
        sp_request_eppn = ticket.service_requested_eppn

    # Availability of "login using another device" is controlled by configuration for now.
    res.other_device = current_app.conf.allow_other_device_logins

    if ticket.is_other_device_2:
        current_app.logger.debug(f'This is already a request to log in to another device, not allowing other_device')
        res.other_device = False

    if not sso_session:
        if sp_request_eppn:
            current_app.logger.info(f'SP requests login by user {sp_request_eppn}')
            _set_user_options(res, sp_request_eppn)
        current_app.logger.debug(f'No SSO session, responding {res}')
        return res.to_dict()

    # Since the user has a session, logout should be shown (to allow change of user)
    res.has_session = True

    if sp_request_eppn and sp_request_eppn != sso_session.eppn:
        current_app.logger.warning(
            f'SP requests login by user {sp_request_eppn}, but session belongs to {sso_session.eppn}'
        )
        # TODO: what's the real course of action here?
    else:
        _set_user_options(res, sso_session.eppn)

    current_app.logger.debug(f'Valid authn options at this time: {res.valid_options}')

    return res.to_dict()


def _get_service_info(ticket: LoginContext) -> Dict[str, Any]:
    if ticket.service_info is not None:
        return ticket.service_info.to_dict()
    return {}


def _set_user_options(res: AuthnOptions, eppn: str) -> None:
    user = current_app.userdb.lookup_user(eppn)
    if user:
        current_app.logger.debug(f'User logging in (from either SSO session, or SP request): {user}')
        if user.credentials.filter(Password):
            current_app.logger.debug(f'User has a Password credential')
            res.password = True

        if user.credentials.filter(FidoCredential):
            current_app.logger.debug(f'User has a FIDO/Webauthn credential')
            res.webauthn = True

        if user.locked_identity.filter(LockedIdentityNin):
            current_app.logger.debug(f'User has a locked NIN -> Freja is possible')
            res.freja_eidplus = True

        if user.mail_addresses.primary:
            # Provide e-mail from (potentially expired) SSO session to frontend, so it can populate
            # the username field for the user
            _mail = user.mail_addresses.primary.email
            current_app.logger.debug(f'User has a primary e-mail -> forced_username {_mail}')
            res.forced_username = _mail
            res.username = False

        res.display_name = user.display_name or user.given_name or res.forced_username
