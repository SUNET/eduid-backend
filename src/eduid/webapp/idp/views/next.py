from dataclasses import asdict
from typing import Any, Dict

from flask import Blueprint, url_for

from eduid.userdb import LockedIdentityNin
from eduid.userdb.credentials import FidoCredential, Password
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.messages import FluxData, error_response, success_response
from eduid.webapp.common.session import session
from eduid.webapp.common.session.logindata import LoginContextOtherDevice, LoginContextSAML
from eduid.webapp.common.session.namespaces import RequestRef
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.helpers import IdPAction, IdPMsg
from eduid.webapp.idp.login import SSO, get_ticket, login_next_step
from eduid.webapp.idp.other_device.device2 import device2_finish
from eduid.webapp.idp.schemas import (
    AuthnOptionsRequestSchema,
    AuthnOptionsResponseSchema,
    NextRequestSchema,
    NextResponseSchema,
)
from eduid.webapp.idp.service import SAMLQueryParams
from saml2 import BINDING_HTTP_POST

next_views = Blueprint('next', __name__, url_prefix='')


@next_views.route('/authn_options', methods=['POST'])
@UnmarshalWith(AuthnOptionsRequestSchema)
@MarshalWith(AuthnOptionsResponseSchema)
def authn_options(ref: RequestRef) -> FluxData:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- Authn options {ref} ---')

    _info = SAMLQueryParams(request_ref=ref)
    ticket = get_ticket(_info, None)
    if not ticket:
        return error_response(message=IdPMsg.bad_ref)
    current_app.logger.debug(f'Extra debug: LoginContext: {asdict(ticket)}')
    current_app.logger.debug(f'Extra debug: Pending request: {ticket.pending_request}')

    payload: Dict[str, Any] = {
        'usernamepassword': True,
        'password': False,
        'other_device': current_app.conf.allow_other_device_logins,
        'webauthn': False,
        'freja_eidplus': False,
    }

    if ticket.is_other_device_2:
        current_app.logger.debug(f'This is already a request to log in to another device, not allowing other_device')
        payload['other_device'] = False

    sso_session = current_app._lookup_sso_session()
    if not sso_session:
        current_app.logger.debug(f'No SSO session, responding {payload}')
        return success_response(payload=payload)

    user = current_app.userdb.lookup_user(sso_session.eppn)
    if user:
        if user.credentials.filter(Password):
            current_app.logger.debug(f'User in SSO session has a Password credential')
            payload['password'] = True

        if user.credentials.filter(FidoCredential):
            current_app.logger.debug(f'User in SSO session has a FIDO/Webauthn credential')
            payload['webauthn'] = True

        if user.locked_identity.filter(LockedIdentityNin):
            current_app.logger.debug(f'User in SSO session has a locked NIN -> Freja is possible')
            payload['freja_eidplus'] = True

        if user.mail_addresses.primary:
            # Provide e-mail from (potentially expired) SSO session to frontend, so it can populate
            # the username field for the user
            _mail = user.mail_addresses.primary.email
            current_app.logger.debug(f'User in SSO session has a primary e-mail -> username {_mail}')
            payload['username'] = _mail

    current_app.logger.debug(f'Responding with authn options: {payload}')
    return success_response(payload=payload)


@next_views.route('/next', methods=['POST'])
@UnmarshalWith(NextRequestSchema)
@MarshalWith(NextResponseSchema)
def next(ref: RequestRef) -> FluxData:
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

    if _next.message == IdPMsg.other_device:
        _payload = {
            'action': IdPAction.OTHER_DEVICE.value,
            'target': url_for('other_device.use_other_1', _external=True),
        }

        return success_response(message=IdPMsg.must_authenticate, payload=_payload,)

    if _next.message == IdPMsg.must_authenticate:
        _payload = {
            'action': IdPAction.PWAUTH.value,
            'target': url_for('pw_auth.pw_auth', _external=True),
        }

        return success_response(message=IdPMsg.must_authenticate, payload=_payload,)

    if _next.message == IdPMsg.mfa_required:
        return success_response(
            message=IdPMsg.mfa_required,
            payload={'action': IdPAction.MFA.value, 'target': url_for('mfa_auth.mfa_auth', _external=True),},
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
