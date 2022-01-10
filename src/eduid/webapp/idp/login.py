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
import json
import pprint
import time
from base64 import b64encode
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Dict, List, Optional
from uuid import uuid4

from defusedxml import ElementTree as DefusedElementTree
from flask import make_response, redirect, render_template, request, url_for
from flask_babel import gettext as _
from pydantic import BaseModel
from werkzeug.exceptions import BadRequest, Forbidden, TooManyRequests
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.misc.encoders import EduidJSONEncoder
from eduid.common.misc.timeutil import utc_now
from eduid.common.utils import urlappend
from eduid.userdb.idp import IdPUser
from eduid.userdb.idp.user import SAMLAttributeSettings
from eduid.webapp.common.api import exceptions
from eduid.webapp.common.session import session
from eduid.webapp.common.session.logindata import LoginContext, LoginContextOtherDevice, LoginContextSAML
from eduid.webapp.common.session.namespaces import IdP_OtherDevicePendingRequest, IdP_SAMLPendingRequest, RequestRef
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
from eduid.webapp.idp.assurance_data import AuthnInfo
from eduid.webapp.idp.helpers import IdPMsg
from eduid.webapp.idp.idp_actions import redirect_to_actions
from eduid.webapp.idp.idp_authn import AuthnData
from eduid.webapp.idp.idp_saml import IdP_SAMLRequest, ResponseArgs, SamlResponse
from eduid.webapp.idp.mfa_action import add_mfa_action, need_security_key, process_mfa_action_results
from eduid.webapp.idp.mischttp import HttpArgs, get_default_template_arguments
from eduid.webapp.idp.other_device_data import OtherDeviceState
from eduid.webapp.idp.service import SAMLQueryParams, Service
from eduid.webapp.idp.sso_session import SSOSession
from eduid.webapp.idp.tou_action import add_tou_action, need_tou_acceptance
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


class NextResult(BaseModel):
    message: IdPMsg
    error: bool = False
    authn_info: Optional[AuthnInfo] = None
    # kludge for the template processing, pydantic doesn't embed dataclasses very well:
    #  TypeError: non-default argument 'mail_addresses' follows default argument
    user: Optional[Any] = None

    class Config:
        # don't reject WerkzeugResponse
        arbitrary_types_allowed = True

    def __str__(self):
        return (
            f'<{self.__class__.__name__}: message={self.message.value}, error={self.error}, authn={self.authn_info}, '
            f'user={self.user}>'
        )


def login_next_step(ticket: LoginContext, sso_session: Optional[SSOSession], template_mode: bool = False) -> NextResult:
    """ The main state machine for the login flow(s). """
    if current_app.conf.allow_other_device_logins:
        if ticket.is_other_device == 1:
            state = current_app.other_device_db.get_state_by_id(ticket.other_device_state_id)
            if (
                state
                and state.expires_at > utc_now()
                and state.state in [OtherDeviceState.NEW, OtherDeviceState.IN_PROGRESS]
            ):
                current_app.logger.debug(f'Logging in using another device, {ticket.other_device_state_id}')
                return NextResult(message=IdPMsg.other_device)

    if not isinstance(sso_session, SSOSession):
        current_app.logger.debug('No SSO session found - initiating authentication')
        return NextResult(message=IdPMsg.must_authenticate)

    user = current_app.userdb.lookup_user(sso_session.eppn)
    if not user:
        current_app.logger.error(f'User with eppn {sso_session.eppn} (from SSO session) not found')
        return NextResult(message=IdPMsg.general_failure, error=True)

    if user.terminated:
        current_app.logger.info(f'User {user} is terminated')
        return NextResult(message=IdPMsg.user_terminated, error=True)

    if template_mode and current_app.conf.enable_legacy_template_mode:
        process_mfa_action_results(user, ticket, sso_session)

    res = NextResult(message=IdPMsg.assurance_failure, error=True)

    try:
        authn_info = assurance.response_authn(ticket, user, sso_session)
        res = NextResult(message=IdPMsg.proceed, authn_info=authn_info)
    except MissingPasswordFactor:
        res = NextResult(message=IdPMsg.must_authenticate)
    except MissingMultiFactor:
        res = NextResult(message=IdPMsg.mfa_required, user=user if template_mode else None)
    except MissingAuthentication:
        res = NextResult(message=IdPMsg.must_authenticate)
    except WrongMultiFactor as exc:
        current_app.logger.info(f'Assurance not possible: {repr(exc)}')
        res = NextResult(message=IdPMsg.swamid_mfa_required, error=True)
    except AssuranceException as exc:
        current_app.logger.info(f'Assurance not possible: {repr(exc)}')
        res = NextResult(message=IdPMsg.assurance_not_possible, error=True)

    if res.message == IdPMsg.must_authenticate:
        # User might not be authenticated enough for e.g. ToU acceptance yet
        return res

    # User is at least partially authenticated, put the eppn in the shared session
    if session.common.eppn and session.common.eppn != user.eppn:
        current_app.logger.warning(f'Refusing to change eppn in session from {session.common.eppn} to {user.eppn}')
        return NextResult(message=IdPMsg.wrong_user, error=True)
    session.common.eppn = user.eppn

    if need_tou_acceptance(user):
        return NextResult(message=IdPMsg.tou_required, user=user if template_mode else None)

    if need_security_key(user, ticket):
        return NextResult(message=IdPMsg.mfa_required, user=user if template_mode else None)

    return res


@dataclass
class SAMLResponseParams:
    url: str
    post_params: Dict[str, str]
    # Parameters for the old template realm
    binding: str
    http_args: HttpArgs


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

        return self._redirect_or_post(_info, BINDING_HTTP_REDIRECT)

    def post(self) -> WerkzeugResponse:
        """
        The HTTP-Post endpoint

        :return: HTTP response
        """
        current_app.logger.debug("--- In SSO POST ---")
        _info = self.unpack_either()

        return self._redirect_or_post(_info, BINDING_HTTP_POST)

    def _redirect_or_post(self, info: SAMLQueryParams, binding: str) -> WerkzeugResponse:
        """ Common code for redirect() and post() endpoints. """

        ticket = get_ticket(info, binding)
        if not ticket:
            # User probably pressed 'back' in the browser after authentication
            current_app.logger.info(f'Redirecting user without a SAML request to {current_app.conf.eduid_site_url}')
            return redirect(current_app.conf.eduid_site_url)

        if current_app.conf.login_bundle_url:
            if info.SAMLRequest:
                # redirect user to the Login javascript bundle
                loc = urlappend(current_app.conf.login_bundle_url, ticket.request_ref)
                current_app.logger.info(f'Redirecting user to login bundle {loc}')
                return redirect(loc)
            else:
                raise BadRequest('No SAMLRequest, and login_bundle_url is set')

        # TODO: Remove all this code, we don't use the template IdP anymore.
        if not current_app.conf.enable_legacy_template_mode:
            raise BadRequest('Template IdP not enabled')

        # please mypy with this legacy code
        assert isinstance(ticket, LoginContextSAML)

        _next = login_next_step(ticket, self.sso_session, template_mode=True)
        current_app.logger.debug(f'Login Next: {_next}')

        if _next.message == IdPMsg.must_authenticate:
            if not self.sso_session:
                current_app.logger.info(f'{ticket.request_ref}: authenticate ip={request.remote_addr}')
            elif ticket.saml_req.force_authn:
                current_app.logger.info(f'{ticket.request_ref}: force_authn sso_session={self.sso_session.public_id}')

            return redirect(url_for('idp.verify') + '?ref=' + ticket.request_ref)

        if _next.message == IdPMsg.user_terminated:
            raise Forbidden('USER_TERMINATED')
        if _next.message == IdPMsg.swamid_mfa_required:
            raise Forbidden('SWAMID_MFA_REQUIRED')
        if _next.message == IdPMsg.wrong_user:
            raise BadRequest('WRONG_USER')

        if _next.message == IdPMsg.tou_required:
            assert isinstance(_next.user, IdPUser)  # please mypy
            add_tou_action(_next.user)
            return redirect_to_actions(_next.user, ticket)

        if _next.message == IdPMsg.mfa_required:
            assert isinstance(_next.user, IdPUser)  # please mypy
            add_mfa_action(_next.user, ticket)
            return redirect_to_actions(_next.user, ticket)

        if _next.message == IdPMsg.proceed:
            assert self.sso_session  # please mypy
            current_app.logger.info(
                f'{ticket.request_ref}: proceeding sso_session={self.sso_session.public_id}, age={self.sso_session.age}'
            )
            current_app.logger.debug(f'Continuing with Authn request {repr(ticket.saml_req.request_id)}')
            assert _next.authn_info  # please mypy
            return self.perform_login(ticket, _next.authn_info)

        raise RuntimeError(f'Don\'t know what to do with {ticket}')

    def perform_login(self, ticket: LoginContextSAML, authn_info: AuthnInfo) -> WerkzeugResponse:
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

        user = current_app.userdb.lookup_user(self.sso_session.eppn)
        if not user:
            current_app.logger.error(f'User with eppn {self.sso_session.eppn} (from SSO session) not found')
            raise Forbidden('User in SSO session not found')

        params = self.get_response_params(authn_info, ticket, user)

        if session.common.eppn and session.common.eppn != user.eppn:
            current_app.logger.warning(f'Refusing to change eppn in session from {session.common.eppn} to {user.eppn}')
            raise BadRequest('WRONG_USER')
        session.common.eppn = user.eppn

        # We're done with this SAML request. Remove it from the session.
        del session.idp.pending_requests[ticket.request_ref]

        return mischttp.create_html_response(params.binding, params.http_args)

    def get_response_params(self, authn_info: AuthnInfo, ticket: LoginContextSAML, user: IdPUser) -> SAMLResponseParams:
        resp_args = self._validate_login_request(ticket)

        try:
            req_authn_context = get_requested_authn_context(ticket)
            current_app.logger.debug(f'Asserting AuthnContext {authn_info} (requested: {req_authn_context})')
        except AttributeError:
            current_app.logger.debug(f'Asserting AuthnContext {authn_info} (none requested)')

        assert self.sso_session  # please mypy
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

        params = {
            'SAMLResponse': b64encode(str(saml_response).encode('utf-8')).decode('ascii'),
            'RelayState': ticket.RelayState,
        }
        return SAMLResponseParams(url=http_args.url, post_params=params, binding=binding, http_args=http_args)

    def _make_saml_response(
        self,
        response_authn: AuthnInfo,
        resp_args: ResponseArgs,
        user: IdPUser,
        ticket: LoginContextSAML,
        sso_session: SSOSession,
    ) -> SamlResponse:
        """
        Create the SAML response using pysaml2 create_authn_response().

        :param resp_args: pysaml2 response arguments
        :param user: IdP user
        :param ticket: Login process state

        :return: SAML response (string)
        """
        sp_entity_categories = ticket.saml_req.sp_entity_attributes.get('http://macedir.org/entity-category', [])
        saml_attribute_settings = SAMLAttributeSettings(
            default_eppn_scope=current_app.conf.default_eppn_scope,
            default_country=current_app.conf.default_country,
            default_country_code=current_app.conf.default_country_code,
            sp_entity_categories=sp_entity_categories,
            esi_ladok_prefix=current_app.conf.esi_ladok_prefix,
        )
        attributes = user.to_saml_attributes(settings=saml_attribute_settings)
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

    def _kantara_log_assertion_id(self, saml_response: str, ticket: LoginContext) -> None:
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

    def _validate_login_request(self, ticket: LoginContextSAML) -> ResponseArgs:
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
        assert isinstance(ticket, LoginContext)
        current_app.logger.debug(f"Validate login request :\n{ticket}")
        current_app.logger.debug(f"AuthnRequest from ticket: {ticket.saml_req!r}")
        return ticket.saml_req.get_response_args(BadRequest, ticket.request_ref)


# -----------------------------------------------------------------------------
# === Authentication ====
# -----------------------------------------------------------------------------


def show_login_page(ticket: LoginContextSAML) -> WerkzeugResponse:
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
    if ticket.pending_request.template_show_msg:
        argv['alert_msg'] = ticket.pending_request.template_show_msg
        ticket.pending_request.template_show_msg = None

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
    if not _ticket:
        raise BadRequest(f'Missing parameter - please re-initiate login')

    # TODO: Remove all this code, we don't use the template IdP anymore.
    if not current_app.conf.enable_legacy_template_mode:
        raise BadRequest('Template IdP not enabled')

    # please mypy with this legacy code
    assert isinstance(_ticket, LoginContextSAML)

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
        _ticket.pending_request.template_show_msg = _('Incorrect username or password')
        current_app.logger.debug(f'Unknown user or wrong password. Redirect => {next_endpoint}')
        return redirect(next_endpoint)

    # Create SSO session
    current_app.logger.debug(f'User {pwauth.user} authenticated OK (SAML id {repr(_ticket.saml_req.request_id)})')
    _authn_credentials: List[AuthnData] = []
    if pwauth.authndata:
        _authn_credentials = [pwauth.authndata]
    _sso_session = SSOSession(
        authn_credentials=_authn_credentials,
        authn_request_id=_ticket.saml_req.request_id,
        eppn=pwauth.user.eppn,
        expires_at=utc_now() + current_app.conf.sso_session_lifetime,
    )

    # This session contains information about the fact that the user was authenticated. It is
    # used to avoid requiring subsequent authentication for the same user during a limited
    # period of time, by storing the session-id in a browser cookie.
    current_app.sso_sessions.save(_sso_session)

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
    # For debugging purposes, save the IdP SSO cookie value in the common session as well.
    # This is because we think we might have issues overwriting cookies in redirect responses.
    session.idp.sso_cookie_val = _sso_session.session_id
    return mischttp.set_sso_cookie(_sso_session.session_id, resp)


# ----------------------------------------------------------------------------
def _add_saml_request_to_session(info: SAMLQueryParams, binding: str) -> RequestRef:
    if info.request_ref:
        # Already present
        return info.request_ref
    if not info.SAMLRequest or binding is None:
        raise ValueError(f"Can't add incomplete query params to session: {info}, binding {binding}")
    request_ref = RequestRef(str(uuid4()))
    session.idp.pending_requests[request_ref] = IdP_SAMLPendingRequest(
        request=info.SAMLRequest, binding=binding, relay_state=info.RelayState
    )
    return request_ref


def get_ticket(info: SAMLQueryParams, binding: Optional[str]) -> Optional[LoginContext]:
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

    if info.request_ref not in session.idp.pending_requests:
        logger.debug(f'Ref {info.request_ref} not found in pending requests: {session.idp.pending_requests.keys()}')
        logger.debug(f'Extra debug, full pending requests: {session.idp.pending_requests}')
        # raise RuntimeError(f'No pending request with ref {info.request_ref} found in session')
        return None

    pending = session.idp.pending_requests[info.request_ref]
    if isinstance(pending, IdP_SAMLPendingRequest):
        return LoginContextSAML(info.request_ref)
    elif isinstance(pending, IdP_OtherDevicePendingRequest):
        logger.debug(f'get_ticket: Loading IdP_OtherDevicePendingRequest (state_id {pending.state_id})')
        state = current_app.other_device_db.get_state_by_id(pending.state_id)
        if not state:
            current_app.logger.debug(f'Other device: Login id {pending.state_id} not found')
            return None
        current_app.logger.debug(f'Loaded other device state: {pending.state_id}')
        current_app.logger.debug(f'Extra debug: Full other device state:\n{state.to_json()}')

        return LoginContextOtherDevice(request_ref=info.request_ref, other_device_req=state)
    else:
        current_app.logger.warning(f'Can\'t parse pending request {info.request_ref}: {pending}')

    return None
