#
# Copyright (c) 2013, 2014, 2016 NORDUnet A/S. All rights reserved.
# Copyright 2012 Roland Hedberg. All rights reserved.
#
# See the file eduid-IdP/LICENSE.txt for license statement.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#          Roland Hedberg
#

"""
Code handling Single Sign On logins.
"""

import hmac
import pprint
import time
from enum import unique
from hashlib import sha256
from typing import Dict, List, Optional
from uuid import uuid4

from defusedxml import ElementTree as DefusedElementTree
from flask import make_response, redirect, render_template, request, url_for
from flask_babel import gettext as _
from pydantic import BaseModel
from werkzeug.exceptions import BadRequest, Forbidden, TooManyRequests
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.userdb.idp import IdPUser
from eduid.userdb.idp.user import SAMLAttributeSettings
from eduid.webapp.common.api import exceptions
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.session import session
from eduid.webapp.common.session.logindata import SSOLoginData
from eduid.webapp.common.session.namespaces import IdP_PendingRequest, RequestRef
from eduid.webapp.idp import assurance, mischttp
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.assurance import (
    AssuranceException,
    MissingAuthentication,
    MissingMultiFactor,
    MissingPasswordFactor,
    WrongMultiFactor,
    get_requested_authn_context,
)
from eduid.webapp.idp.idp_actions import check_for_pending_actions
from eduid.webapp.idp.idp_authn import AuthnData
from eduid.webapp.idp.idp_saml import AuthnInfo, IdP_SAMLRequest, ResponseArgs, SamlResponse, gen_key
from eduid.webapp.idp.mischttp import get_default_template_arguments
from eduid.webapp.idp.service import SAMLQueryParams, Service
from eduid.webapp.idp.sso_session import SSOSession
from eduid.webapp.idp.util import b64encode
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT


class MustAuthenticate(Exception):
    """
    This exception is raised in special circumstances when the IdP decides
    that a user really must authenticate again, even though there exist an
    SSO session.
    """


# -----------------------------------------------------------------------------
# === Single log in ====
# -----------------------------------------------------------------------------


@unique
class IdPMsg(str, TranslatableMsg):
    user_terminated = 'idp.user_terminated'
    must_authenticate = 'idp.must_authenticate'
    swamid_mfa_required = 'idp.swamid_mfa_required'
    mfa_required = 'idp.mfa_required'
    assurance_not_possible = 'idp.assurance_not_possible'
    assurance_failure = 'idp.assurance_failure'
    action_required = 'idp.action_required'  # Shouldn't actually be returned to the frontend
    proceed = 'idp.proceed'  # Shouldn't actually be returned to the frontend
    wrong_user = 'wrong_user'


class NextResult(BaseModel):
    message: IdPMsg
    error: bool = False
    endpoint: Optional[str] = None
    action_response: Optional[WerkzeugResponse] = None
    authn_info: Optional[AuthnInfo] = None

    class Config:
        # don't reject WerkzeugResponse
        arbitrary_types_allowed = True


def login_next_step(ticket: SSOLoginData, sso_session: Optional[SSOSession]) -> NextResult:
    """ The main state machine for the login flow(s). """
    if not isinstance(sso_session, SSOSession):
        return NextResult(message=IdPMsg.must_authenticate, endpoint=url_for('idp.verify'))

    user = sso_session.idp_user

    if user.terminated:
        current_app.logger.info(f'User {user} is terminated')
        return NextResult(message=IdPMsg.user_terminated, error=True)

    res: Optional[NextResult] = None
    authn_info = None

    try:
        authn_info = assurance.response_authn(ticket, user, sso_session)
    except MissingPasswordFactor:
        return NextResult(message=IdPMsg.must_authenticate, endpoint=url_for('idp.verify'))
    except MissingMultiFactor as exc:
        # Postpone this result until after checking for pending actions
        current_app.logger.debug(
            f'Assurance not possible: {repr(exc)} (postponing this until after checking for actions)'
        )
        res = NextResult(message=IdPMsg.mfa_required, error=True)
    except MissingAuthentication:
        return NextResult(message=IdPMsg.must_authenticate, endpoint=url_for('idp.verify'))
    except WrongMultiFactor as exc:
        current_app.logger.info(f'Assurance not possible: {repr(exc)}')
        return NextResult(message=IdPMsg.swamid_mfa_required, error=True)
    except AssuranceException as exc:
        current_app.logger.info(f'Assurance not possible: {repr(exc)}')
        return NextResult(message=IdPMsg.assurance_not_possible, error=True)

    # OLD:
    if 'user_eppn' in session and session['user_eppn'] != user.eppn:
        current_app.logger.warning(f'Refusing to change eppn in session from {session["user_eppn"]} to {user.eppn}')
        return NextResult(message=IdPMsg.wrong_user, error=True)
    session['user_eppn'] = user.eppn
    # NEW:
    if session.common.eppn and session.common.eppn != user.eppn:
        current_app.logger.warning(f'Refusing to change eppn in session from {session.common.eppn} to {user.eppn}')
        return NextResult(message=IdPMsg.wrong_user, error=True)
    session.common.eppn = user.eppn

    action_response = check_for_pending_actions(user, ticket, sso_session)
    if action_response:
        return NextResult(message=IdPMsg.action_required, action_response=action_response)

    if res:
        return res

    if not authn_info:
        return NextResult(message=IdPMsg.assurance_failure, error=True)

    return NextResult(message=IdPMsg.proceed, authn_info=authn_info)


class SSO(Service):
    """
    Single Sign On service.
    """

    def __init__(self, sso_session: Optional[SSOSession]):
        super().__init__(sso_session)

    def redirect(self) -> WerkzeugResponse:
        """This is the HTTP-redirect endpoint.

        :return: HTTP response
        """
        current_app.logger.debug("--- In SSO Redirect ---")
        _info = self.unpack_redirect()
        current_app.logger.debug(f'Unpacked redirect :\n{pprint.pformat(_info)}')

        ticket = get_ticket(_info, BINDING_HTTP_REDIRECT)
        return self._redirect_or_post(ticket)

    def post(self) -> WerkzeugResponse:
        """
        The HTTP-Post endpoint

        :return: HTTP response
        """
        current_app.logger.debug("--- In SSO POST ---")
        _info = self.unpack_either()

        ticket = get_ticket(_info, BINDING_HTTP_POST)
        return self._redirect_or_post(ticket)

    def _redirect_or_post(self, ticket: SSOLoginData) -> WerkzeugResponse:
        """ Common code for redirect() and post() endpoints. """

        _next = login_next_step(ticket, self.sso_session)
        current_app.logger.debug(f'Login Next: {_next}')

        if _next.message == IdPMsg.must_authenticate:
            if not self.sso_session:
                current_app.logger.info(f'{ticket.request_ref}: authenticate ip={request.remote_addr}')
            elif ticket.saml_req.force_authn:
                current_app.logger.info(f'{ticket.request_ref}: force_authn sso_session={self.sso_session.public_id}')

            # Don't use _next.endpoint here, even though it happens to be this same URL for now.
            # _next.endpoint is for the API interface, this is the old template realm.
            return redirect(url_for('idp.verify') + '?ref=' + ticket.request_ref)

        if _next.message == IdPMsg.user_terminated:
            raise Forbidden('USER_TERMINATED')
        if _next.message == IdPMsg.swamid_mfa_required:
            raise Forbidden('SWAMID_MFA_REQUIRED')
        if _next.message == IdPMsg.mfa_required:
            raise Forbidden('MFA_REQUIRED')

        if _next.message == IdPMsg.action_required:
            current_app.logger.debug('Sending user to actions')
            assert _next.action_response  # please mypy
            return _next.action_response

        if _next.message == IdPMsg.proceed:
            assert self.sso_session  # please mypy
            _ttl = current_app.conf.sso_session_lifetime - self.sso_session.minutes_old
            current_app.logger.info(
                f'{ticket.request_ref}: proceeding sso_session={self.sso_session.public_id}, ttl={_ttl:}m'
            )
            current_app.logger.debug(f'Continuing with Authn request {repr(ticket.saml_req.request_id)}')
            assert _next.authn_info  # please mypy
            return self.perform_login(ticket, _next.authn_info)

        raise RuntimeError(f'Don\'t know what to do with {ticket}')

    def perform_login(self, ticket: SSOLoginData, authn_info: AuthnInfo) -> WerkzeugResponse:
        """
        Validate request, and then proceed with creating an AuthnResponse and
        invoking the 'outgoing' SAML2 binding.

        :param ticket: Login process state
        :return: Response
        """
        current_app.logger.debug("\n\n---\n\n")
        current_app.logger.debug("--- In SSO.perform_login() ---")

        if not isinstance(self.sso_session, SSOSession):
            raise RuntimeError(f'self.sso_session is not of type {SSOSession} ({type(self.sso_session)})')

        user = self.sso_session.idp_user

        resp_args = self._validate_login_request(ticket)

        # OLD:
        if 'user_eppn' in session and session['user_eppn'] != user.eppn:
            current_app.logger.warning(f'Refusing to change eppn in session from {session["user_eppn"]} to {user.eppn}')
        else:
            session['user_eppn'] = user.eppn
        # NEW:
        if session.common.eppn and session.common.eppn != user.eppn:
            current_app.logger.warning(f'Refusing to change eppn in session from {session.common.eppn} to {user.eppn}')
        else:
            session.common.eppn = user.eppn

        action_response = check_for_pending_actions(user, ticket, self.sso_session)
        if action_response:
            return action_response

        # We won't get here until the user has completed all login actions

        try:
            req_authn_context = get_requested_authn_context(ticket)
            current_app.logger.debug(f'Asserting AuthnContext {authn_info} (requested: {req_authn_context})')
        except AttributeError:
            current_app.logger.debug(f'Asserting AuthnContext {authn_info} (none requested)')

        saml_response = self._make_saml_response(authn_info, resp_args, user, ticket, self.sso_session)

        binding = resp_args['binding']
        destination = resp_args['destination']
        http_args = ticket.saml_req.apply_binding(resp_args, ticket.RelayState, saml_response)

        # INFO-Log the SSO session id and the AL and destination
        current_app.logger.info(f'{ticket.request_ref}: response authn={authn_info}, dst={destination}')
        self._fticks_log(
            relying_party=resp_args.get('sp_entity_id', destination),
            authn_method=authn_info.class_ref,
            user_id=str(user.user_id),
        )

        # We're done with this SAML request. Remove it from the session.
        del session.idp.pending_requests[ticket.request_ref]

        return mischttp.create_html_response(binding, http_args)

    def _make_saml_response(
        self,
        response_authn: AuthnInfo,
        resp_args: ResponseArgs,
        user: IdPUser,
        ticket: SSOLoginData,
        sso_session: SSOSession,
    ) -> SamlResponse:
        """
        Create the SAML response using pysaml2 create_authn_response().

        :param resp_args: pysaml2 response arguments
        :param user: IdP user
        :param ticket: Login process state

        :return: SAML response (string)
        """
        saml_attribute_settings = SAMLAttributeSettings(
            default_eppn_scope=current_app.conf.default_eppn_scope,
            default_country=current_app.conf.default_country,
            default_country_code=current_app.conf.default_country_code,
        )
        attributes = user.to_saml_attributes(saml_attribute_settings, current_app.logger)
        # Generate eduPersonTargetedID
        if current_app.conf.eduperson_targeted_id_secret_key:
            sp_identifier = resp_args.get('sp_entity_id', resp_args['destination'])
            attributes["eduPersonTargetedID"] = self._get_eptid(relying_party=sp_identifier, user_eppn=user.eppn)

        # Add a list of credentials used in a private attribute that will only be
        # released to the eduID authn component
        attributes['eduidIdPCredentialsUsed'] = [x.cred_id for x in sso_session.authn_credentials]
        for k, v in response_authn.authn_attributes.items():
            if k in attributes:
                current_app.logger.debug(
                    f'Overwriting user attribute {k} ({attributes[k]!r}) with authn attribute value {v!r}'
                )
            else:
                current_app.logger.debug(f'Adding attribute {k} with value from authn process: {v}')
            attributes[k] = v
        # Set digest_alg and sign_alg to a sane default value
        try:
            resp_args['digest_alg'] = current_app.conf.supported_digest_algorithms[0]
        except IndexError:
            pass
        try:
            resp_args['sign_alg'] = current_app.conf.supported_signing_algorithms[0]
        except IndexError:
            pass
        # Try to pick best signing and digest algorithms from what the SP supports
        for digest_alg in current_app.conf.supported_digest_algorithms:
            if digest_alg in ticket.saml_req.sp_digest_algs:
                resp_args['digest_alg'] = digest_alg
                break
        for sign_alg in current_app.conf.supported_signing_algorithms:
            if sign_alg in ticket.saml_req.sp_sign_algs:
                resp_args['sign_alg'] = sign_alg
                break
        if current_app.conf.debug:
            # Only perform expensive parse/pretty-print if debugging
            pp = pprint.PrettyPrinter()
            current_app.logger.debug(
                f'Creating an AuthnResponse to SAML request {repr(ticket.saml_req.request_id)}:\nUser {user}\n\n'
                f'Attributes:\n{pp.pformat(attributes)},\n\n'
                f'Response args:\n{pp.pformat(resp_args)},\n\n'
                f'Authn:\n{pp.pformat(response_authn)}\n'
            )

        saml_response = ticket.saml_req.make_saml_response(attributes, user.eppn, response_authn, resp_args)
        self._kantara_log_assertion_id(saml_response, ticket)

        return saml_response

    def _kantara_log_assertion_id(self, saml_response: str, ticket: SSOLoginData) -> None:
        """
        Log the assertion id, which _might_ be required by Kantara.

        :param saml_response: authn response as a compact XML string
        :param ticket: Login process state

        :return: None
        """
        printed = False
        try:
            parser = DefusedElementTree.DefusedXMLParser()
            xml = DefusedElementTree.XML(str(saml_response), parser)

            # For debugging, it is very useful to get the full SAML response pretty-printed in the logfile directly
            current_app.logger.debug(f'Created AuthNResponse :\n\n{DefusedElementTree.tostring(xml)}\n\n')
            printed = True

            attrs = xml.attrib
            assertion = xml.find('{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
            current_app.logger.info(
                '{!s}: id={!s}, in_response_to={!s}, assertion_id={!s}'.format(
                    ticket.request_ref, attrs['ID'], attrs['InResponseTo'], assertion.get('ID')
                )
            )
        except Exception as exc:
            current_app.logger.debug(f'Could not parse message as XML: {exc!r}')
            if not printed:
                # Fall back to logging the whole response
                current_app.logger.info(f'{ticket.request_ref}: authn response: {saml_response}')
        return None

    def _fticks_log(self, relying_party: str, authn_method: str, user_id: str) -> None:
        """
        Perform SAML F-TICKS logging, for statistics in the SWAMID federation.

        :param relying_party: The entity id of the relying party (SP).
        :param authn_method: The URN of the authentication method used.
        :param user_id: Unique user id.
        """
        if not current_app.conf.fticks_secret_key:
            return
        # Default format string:
        #   'F-TICKS/SWAMID/2.0#TS={ts}#RP={rp}#AP={ap}#PN={pn}#AM={am}#',
        _timestamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
        _anon_userid = hmac.new(
            bytes(current_app.conf.fticks_secret_key, 'ascii'), msg=bytes(user_id, 'ascii'), digestmod=sha256
        ).hexdigest()
        msg = current_app.conf.fticks_format_string.format(
            ts=_timestamp, rp=relying_party, ap=current_app.IDP.config.entityid, pn=_anon_userid, am=authn_method,
        )
        current_app.logger.info(msg)

    @staticmethod
    def _get_eptid(relying_party: str, user_eppn: str) -> List[Dict[str, str]]:
        """
        Generate eduPersonTargetedID

        eduPersonTargetedID value is a tuple consisting of an opaque identifier for the principal,
        a name for the source of the identifier, and a name for the intended audience of the identifier.

        Per the SAML format definition, the identifier portion MUST NOT exceed 256 characters, and the
        source and audience URI values MUST NOT exceed 1024 characters.

        :param relying_party: The entity id of the relying party (SP).
        :param user_eppn: Unique user identifier
        """
        _sp_user_id = f'{relying_party}-{user_eppn}'
        _anon_sp_userid = hmac.new(
            bytes(current_app.conf.eduperson_targeted_id_secret_key, 'ascii'),
            msg=bytes(_sp_user_id, 'ascii'),
            digestmod=sha256,
        ).hexdigest()

        return [
            {
                "text": _anon_sp_userid,
                "NameQualifier": current_app.IDP.config.entityid,
                "SPNameQualifier": relying_party,
            }
        ]

    def _validate_login_request(self, ticket: SSOLoginData) -> ResponseArgs:
        """
        Validate the validity of the SAML request we are going to answer with
        an assertion.

        Checks that the SP is known through metadata.

        Figures out how to respond to this request. Return a dictionary like

          {'destination': 'https://sp.example.org/saml2/acs/',
           'name_id_policy': <saml2.samlp.NameIDPolicy object>,
           'sp_entity_id': 'https://sp.example.org/saml2/metadata/',
           'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
           'in_response_to': 'id-4c45b079f571c57aef34aaaaac4295c9'
           }

        but we dress it up as a ResponseArgs to allow type checking to ensure
        it is used with the right functions later.

        :param ticket: State for this request
        :return: pysaml2 response creation data
        """
        assert isinstance(ticket, SSOLoginData)
        current_app.logger.debug(f"Validate login request :\n{ticket}")
        current_app.logger.debug(f"AuthnRequest from ticket: {ticket.saml_req!r}")
        return ticket.saml_req.get_response_args(BadRequest, ticket.request_ref)


# -----------------------------------------------------------------------------
# === Authentication ====
# -----------------------------------------------------------------------------


def show_login_page(ticket: SSOLoginData) -> WerkzeugResponse:
    _username = ''
    _login_subject = ticket.saml_req.login_subject
    if _login_subject is not None:
        current_app.logger.debug(f'Login subject: {_login_subject}')
        # Login subject might be set by the idpproxy when requesting the user to do MFA step up
        if current_app.conf.default_eppn_scope is not None and _login_subject.endswith(
            current_app.conf.default_eppn_scope
        ):
            # remove the @scope
            _username = _login_subject[: -(len(current_app.conf.default_eppn_scope) + 1)]

    argv = get_default_template_arguments(current_app.conf)
    argv.update(
        {
            'action': url_for('idp.verify'),
            'alert_msg': '',
            'ref': ticket.request_ref,
            'password': '',
            'username': _username,
        }
    )

    # Set alert msg if found in the session
    if ticket.saml_data.template_show_msg:
        argv['alert_msg'] = ticket.saml_data.template_show_msg
        ticket.saml_data.template_show_msg = None

    current_app.logger.debug(f'Login page HTML substitution arguments :\n{pprint.pformat(argv)}')

    html = render_template('login.jinja2', **argv)
    return make_response(html)


def do_verify() -> WerkzeugResponse:
    """
    Perform authentication of user based on user provided credentials.

    What kind of authentication to perform was chosen by SSO._not_authn() when
    the login web page was to be rendered. It is passed to this function through
    an HTTP POST parameter (authn_reference).

    This function should not be thought of as a "was login successful" or not.
    It will figure out what authentication level to assert based on the authncontext
    requested, and the actual authentication that succeeded.

    :return: Does not return
    :raise eduid_idp.mischttp.Redirect: On successful authentication, redirect to redirect_uri.
    """
    query = mischttp.get_post()
    # extract password to keep it away from as much code as possible
    password = query.pop('password', None)
    if password:
        query['password'] = '<redacted>'
    current_app.logger.debug(f'do_verify parsed query :\n{pprint.pformat(query)}')

    if 'ref' not in query:
        raise BadRequest(f'Missing parameter - please re-initiate login')
    _info = SAMLQueryParams(request_ref=query['ref'])
    _ticket = get_ticket(_info, None)

    authn_ref = get_requested_authn_context(_ticket)
    current_app.logger.debug(f'Authenticating with {repr(authn_ref)}')

    # Create an URL for redirecting the user back to the SSO redirect endpoint after this
    # function - regardless of if authentication was successful or not. The only difference
    # when authentication is successful is that a SSO session is created, and a reference
    # to it set in a cookie in the redirect response.
    next_endpoint = url_for('idp.sso_redirect') + '?ref=' + _ticket.request_ref

    if not password or 'username' not in query:
        current_app.logger.debug(f'Credentials not supplied. Redirect => {next_endpoint}')
        return redirect(next_endpoint)

    try:
        pwauth = current_app.authn.password_authn(query['username'].strip(), password)
    except exceptions.EduidTooManyRequests as e:
        raise TooManyRequests(e.args[0])
    except exceptions.EduidForbidden as e:
        raise Forbidden(e.args[0])
    finally:
        del password  # keep out of any exception logs

    if not pwauth:
        current_app.logger.info(f'{_ticket.request_ref}: Password authentication failed')
        _ticket.saml_data.template_show_msg = _('Incorrect username or password')
        current_app.logger.debug(f'Unknown user or wrong password. Redirect => {next_endpoint}')
        return redirect(next_endpoint)

    # Create SSO session
    current_app.logger.debug(f'User {pwauth.user} authenticated OK (SAML id {repr(_ticket.saml_req.request_id)})')
    _authn_credentials: List[AuthnData] = []
    if pwauth.authndata:
        _authn_credentials = [pwauth.authndata]
    _sso_session = SSOSession(
        user_id=pwauth.user.user_id,
        authn_request_id=_ticket.saml_req.request_id,
        authn_credentials=_authn_credentials,
        idp_user=pwauth.user,
        eppn=pwauth.user.eppn,
    )

    # This session contains information about the fact that the user was authenticated. It is
    # used to avoid requiring subsequent authentication for the same user during a limited
    # period of time, by storing the session-id in a browser cookie.
    current_app.sso_sessions.save(_sso_session)
    current_app.logger.debug(f'Saved SSO session {repr(_sso_session.session_id)}')

    # INFO-Log the request id (sha1 of SAML request) and the sso_session
    current_app.logger.info(
        f'{_ticket.request_ref}: login sso_session={_sso_session.public_id}, authn={authn_ref}, user={pwauth.user}'
    )

    # Remember the password credential used for this particular request
    session.idp.log_credential_used(_ticket.request_ref, pwauth.credential, pwauth.timestamp)

    # Now that an SSO session has been created, redirect the users browser back to
    # the main entry point of the IdP (the SSO redirect endpoint).
    current_app.logger.debug(f'Redirecting user back to the SSO redirect endpoint => {next_endpoint}')
    resp = redirect(next_endpoint)
    # By base64-encoding this string, we should remain interoperable with the old CherryPy based IdP. Fingers crossed.
    b64_session_id = b64encode(_sso_session.session_id)
    # For debugging purposes, save the IdP SSO cookie value in the common session as well.
    # This is because we think we might have issues overwriting cookies in redirect responses.
    session.idp.sso_cookie_val = b64_session_id
    return mischttp.set_sso_cookie(b64_session_id, resp)


# ----------------------------------------------------------------------------
def _add_saml_request_to_session(info: SAMLQueryParams, binding: str) -> RequestRef:
    if info.request_ref:
        # Already present
        return info.request_ref
    if not info.SAMLRequest or binding is None:
        raise ValueError(f"Can't add incomplete query params to session: {info}, binding {binding}")
    request_ref = RequestRef(str(uuid4()))
    session.idp.pending_requests[request_ref] = IdP_PendingRequest(
        request=info.SAMLRequest, binding=binding, relay_state=info.RelayState
    )
    return request_ref


def get_ticket(info: SAMLQueryParams, binding: Optional[str]) -> SSOLoginData:
    """
    Get the SSOLoginData from the eduid.webapp.common session, or from query parameters.
    """
    logger = current_app.logger

    if info.SAMLRequest:
        if binding is None:
            raise ValueError('Binding must be supplied to add SAML request to session')
        info.request_ref = _add_saml_request_to_session(info, binding)
        logger.debug(f'Added SAML request to session, got reference {info.request_ref}')

    if not info.request_ref:
        raise BadRequest('Bad request, please re-initiate login')

    ticket = SSOLoginData(request_ref=info.request_ref)
    ticket.saml_req = IdP_SAMLRequest(ticket.SAMLRequest, ticket.binding, current_app.IDP, debug=current_app.conf.debug)
    return ticket
