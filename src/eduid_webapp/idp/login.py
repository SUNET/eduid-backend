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
from dataclasses import replace
from hashlib import sha256
from html import escape, unescape
from typing import Mapping, Optional

from defusedxml import ElementTree as DefusedElementTree
from flask import make_response, redirect, render_template, request
from flask_babel import gettext as _
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from werkzeug.exceptions import BadRequest, Forbidden, InternalServerError, TooManyRequests
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid_common.api import exceptions
from eduid_common.session import session
from eduid_common.session.logindata import SSOLoginData
from eduid_userdb.idp import IdPUser
from eduid_userdb.idp.user import SAMLAttributeSettings

from eduid_webapp.idp import assurance, mischttp
from eduid_webapp.idp.app import current_idp_app as current_app
from eduid_webapp.idp.assurance import AssuranceException, MissingMultiFactor, WrongMultiFactor
from eduid_webapp.idp.idp_actions import check_for_pending_actions
from eduid_webapp.idp.idp_saml import (
    AuthnInfo,
    IdP_SAMLRequest,
    ResponseArgs,
    SAMLParseError,
    SAMLValidationError,
    gen_key,
)
from eduid_webapp.idp.service import Service
from eduid_webapp.idp.sso_session import SSOSession
from eduid_webapp.idp.util import b64encode, get_requested_authn_context


class MustAuthenticate(Exception):
    """
    This exception is raised in special circumstances when the IdP decides
    that a user really must authenticate again, even though there exist an
    SSO session.
    """


# -----------------------------------------------------------------------------
# === Single log in ====
# -----------------------------------------------------------------------------


class SSO(Service):
    """
    Single Sign On service.

    :param sso_session: SSO session
    :param context: IdP context
    """

    def __init__(self, sso_session: SSOSession):
        super().__init__(sso_session)

    def perform_login(self, ticket: SSOLoginData) -> WerkzeugResponse:
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

        session['user_eppn'] = user.eppn

        action_response = check_for_pending_actions(user, ticket, self.sso_session)
        if action_response:
            return action_response

        # We won't get here until the user has completed all login actions

        response_authn = self._get_login_response_authn(ticket, user)

        saml_response = self._make_saml_response(response_authn, resp_args, user, ticket, self.sso_session)

        binding_out = resp_args['binding_out']
        destination = resp_args['destination']
        http_args = ticket.saml_req.apply_binding(resp_args, ticket.RelayState, str(saml_response))

        # INFO-Log the SSO session id and the AL and destination
        current_app.logger.info(f'{ticket.key}: response authn={response_authn}, dst={destination}')
        self._fticks_log(
            relying_party=resp_args.get('sp_entity_id', destination),
            authn_method=response_authn.class_ref,
            user_id=str(user.user_id),
        )

        return mischttp.create_html_response(binding_out, http_args)

    def _make_saml_response(
        self, response_authn: AuthnInfo, resp_args: ResponseArgs, user: IdPUser, ticket: SSOLoginData, sso_session
    ):
        """
        Create the SAML response using pysaml2 create_authn_response().

        :param resp_args: pysaml2 response arguments
        :param user: IdP user
        :param ticket: Login process state

        :return: SAML response in lxml format
        """
        saml_attribute_settings = SAMLAttributeSettings(
            default_eppn_scope=current_app.config.default_eppn_scope,
            default_country=current_app.config.default_country,
            default_country_code=current_app.config.default_country_code,
            default_scoped_affiliation=current_app.config.default_scoped_affiliation,
        )
        attributes = user.to_saml_attributes(saml_attribute_settings, current_app.logger)
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
            resp_args['digest_alg'] = current_app.config.supported_digest_algorithms[0]
        except IndexError:
            pass
        try:
            resp_args['sign_alg'] = current_app.config.supported_signing_algorithms[0]
        except IndexError:
            pass
        # Try to pick best signing and digest algorithms from what the SP supports
        for digest_alg in current_app.config.supported_digest_algorithms:
            if digest_alg in ticket.saml_req.sp_digest_algs:
                resp_args['digest_alg'] = digest_alg
                break
        for sign_alg in current_app.config.supported_signing_algorithms:
            if sign_alg in ticket.saml_req.sp_sign_algs:
                resp_args['sign_alg'] = sign_alg
                break
        if current_app.config.debug:
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
                    ticket.key, attrs['ID'], attrs['InResponseTo'], assertion.get('ID')
                )
            )

            return DefusedElementTree.tostring(xml)
        except Exception as exc:
            current_app.logger.debug(f'Could not parse message as XML: {exc!r}')
            if not printed:
                # Fall back to logging the whole response
                current_app.logger.info(f'{ticket.key}: authn response: {saml_response}')

    def _fticks_log(self, relying_party: str, authn_method: str, user_id: str) -> None:
        """
        Perform SAML F-TICKS logging, for statistics in the SWAMID federation.

        :param relying_party: The entity id of the relying party (SP).
        :param authn_method: The URN of the authentication method used.
        :param user_id: Unique user id.
        """
        if not current_app.config.fticks_secret_key:
            return
        # Default format string:
        #   'F-TICKS/SWAMID/2.0#TS={ts}#RP={rp}#AP={ap}#PN={pn}#AM={am}#',
        _timestamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
        _anon_userid = hmac.new(
            bytes(current_app.config.fticks_secret_key, 'ascii'), msg=bytes(user_id, 'ascii'), digestmod=sha256
        ).hexdigest()
        msg = current_app.config.fticks_format_string.format(
            ts=_timestamp, rp=relying_party, ap=current_app.IDP.config.entityid, pn=_anon_userid, am=authn_method,
        )
        current_app.logger.info(msg)

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
        return ticket.saml_req.get_response_args(BadRequest, ticket.key)

    def _get_login_response_authn(self, ticket: SSOLoginData, user: IdPUser) -> AuthnInfo:
        """
        Figure out what AuthnContext to assert in the SAML response.

        The 'highest' Assurance-Level (AL) asserted is basically min(ID-proofing-AL, Authentication-AL).

        What AuthnContext is asserted is also heavily influenced by what the SP requested.

        :param ticket: State for this request
        :param user: The user for whom the assertion will be made
        :return: Authn information
        """
        if current_app.config.debug:
            current_app.logger.debug(f'MFA credentials logged in the ticket: {ticket.mfa_action_creds}')
            current_app.logger.debug(f'External MFA credential logged in the ticket: {ticket.mfa_action_external}')
            current_app.logger.debug(f'Credentials used in this SSO session:\n{self.sso_session.authn_credentials}')
            _creds_as_strings = [str(_cred) for _cred in user.credentials.to_list()]
            current_app.logger.debug(f'User credentials:\n{_creds_as_strings}')

        # Decide what AuthnContext to assert based on the one requested in the request
        # and the authentication performed

        req_authn_context = get_requested_authn_context(ticket.saml_req)

        try:
            resp_authn = assurance.response_authn(req_authn_context, user, self.sso_session, current_app.logger)
        except WrongMultiFactor as exc:
            current_app.logger.info(f'Assurance not possible: {exc!r}')
            raise Forbidden('SWAMID_MFA_REQUIRED')
        except MissingMultiFactor as exc:
            current_app.logger.info(f'Assurance not possible: {exc!r}')
            raise Forbidden('MFA_REQUIRED')
        except AssuranceException as exc:
            current_app.logger.info(f'Assurance not possible: {exc!r}')
            raise MustAuthenticate()

        current_app.logger.debug(f'Response Authn context class: {resp_authn!r}')

        try:
            current_app.logger.debug(f'Asserting AuthnContext {resp_authn!r} (requested: {req_authn_context!r})')
        except AttributeError:
            current_app.logger.debug(f'Asserting AuthnContext {resp_authn!r} (none requested)')

        # Augment the AuthnInfo with the authn_timestamp before returning it
        return replace(resp_authn, instant=int(self.sso_session.authn_timestamp.timestamp()))

    def redirect(self) -> WerkzeugResponse:
        """This is the HTTP-redirect endpoint.

        :return: HTTP response
        """
        current_app.logger.debug("--- In SSO Redirect ---")
        _info = self.unpack_redirect()
        current_app.logger.debug(f'Unpacked redirect :\n{pprint.pformat(_info)}')

        ticket = _get_ticket(_info, BINDING_HTTP_REDIRECT)
        return self._redirect_or_post(ticket)

    def post(self) -> WerkzeugResponse:
        """
        The HTTP-Post endpoint

        :return: HTTP response
        """
        current_app.logger.debug("--- In SSO POST ---")
        _info = self.unpack_either()

        ticket = _get_ticket(_info, BINDING_HTTP_POST)
        return self._redirect_or_post(ticket)

    def _redirect_or_post(self, ticket: SSOLoginData) -> WerkzeugResponse:
        """ Common code for redirect() and post() endpoints. """

        if self.sso_session:
            if hasattr(self.sso_session, 'idp_user') and self.sso_session.idp_user.terminated:
                current_app.logger.info(f'User {self.sso_session.idp_user} is terminated')
                current_app.logger.debug(f'User terminated: {self.sso_session.idp_user.terminated}')
                raise Forbidden('USER_TERMINATED')

        _force_authn = self._should_force_authn(ticket)

        if self.sso_session and not _force_authn:
            _ttl = current_app.config.sso_session_lifetime - self.sso_session.minutes_old
            current_app.logger.info(f'{ticket.key}: proceeding sso_session={self.sso_session.public_id}, ttl={_ttl:}m')
            current_app.logger.debug(f'Continuing with Authn request {repr(ticket.saml_req.request_id)}')
            try:
                return self.perform_login(ticket)
            except MustAuthenticate:
                _force_authn = True

        if not self.sso_session:
            current_app.logger.info(f'{ticket.key}: authenticate ip={request.remote_addr}')
        elif _force_authn:
            current_app.logger.info(f'{ticket.key}: force_authn sso_session={self.sso_session.public_id}')

        return self._not_authn(ticket)

    def _should_force_authn(self, ticket: SSOLoginData) -> bool:
        """
        Check if the IdP should force authentication of this request.

        Will check SAML ForceAuthn but avoid endless loops of forced authentications
        by looking if the SSO session says authentication was actually performed
        based on this SAML request.
        """
        if not ticket.saml_req.force_authn:
            current_app.logger.debug(f'SAML request {repr(ticket.saml_req.request_id)} does not have ForceAuthn')
            return False
        if not self.sso_session:
            current_app.logger.debug('Force authn without session - ignoring')
            return True
        if ticket.saml_req.request_id != self.sso_session.authn_request_id:
            current_app.logger.debug(
                f'Forcing authentication because of ForceAuthn with SSO session id '
                f'{self.sso_session.authn_request_id} != this requests {ticket.saml_req.request_id}'
            )
            return True
        current_app.logger.debug(
            f'Ignoring ForceAuthn, authn already performed for SAML request {repr(ticket.saml_req.request_id)}'
        )
        return False

    def _not_authn(self, ticket: SSOLoginData) -> WerkzeugResponse:
        """
        Authenticate user. Either, the user hasn't logged in yet,
        or the service provider forces re-authentication.
        :param ticket: SSOLoginData instance
        :returns: HTTP response
        """
        assert isinstance(ticket, SSOLoginData)
        # TODO: Use flask url_for below in function do_verify(), instead of passing the current URL from here
        redirect_uri = mischttp.geturl(query=False)

        req_authn_context = get_requested_authn_context(ticket.saml_req)
        current_app.logger.debug(f'Do authentication, requested auth context : {req_authn_context!r}')

        return self._show_login_page(ticket, req_authn_context, redirect_uri)

    def _show_login_page(
        self, ticket: SSOLoginData, requested_authn_context: Optional[str], redirect_uri
    ) -> WerkzeugResponse:
        """
        Display the login form for all authentication methods.

        SSO._not_authn() chooses what authentication method to use based on
        requested AuthnContext and local configuration, and then calls this method
        to render the login page for this method.

        :param ticket: Login session state (not SSO session state)
        :param requested_authn_context: Requested authentication context class
        :param redirect_uri: string with URL to proceed to after authentication

        :return: HTTP response
        """
        argv = mischttp.get_default_template_arguments(current_app.config)
        argv.update(
            {
                'action': '/verify',
                'alert_msg': '',
                # TODO: remove key from response, doesn't seem to be needed
                'key': ticket.key,
                'password': '',
                'redirect_uri': redirect_uri,
                'username': '',
                # SAMLRequest, RelayState and binding are used to re-create the ticket state if not found using `key'
                'SAMLRequest': escape(ticket.SAMLRequest, quote=True),
                'RelayState': escape(ticket.RelayState, quote=True),
                'binding': escape(ticket.binding, quote=True),
            }
        )
        if requested_authn_context is not None:
            argv['authn_reference'] = requested_authn_context

        # Set alert msg if FailCount is greater than zero
        if ticket.FailCount:
            argv["alert_msg"] = _('Incorrect username or password')

        try:
            argv["sp_entity_id"] = ticket.saml_req.sp_entity_id
        except KeyError:
            pass

        current_app.logger.debug(f'Login page HTML substitution arguments :\n{pprint.pformat(argv)}')

        html = render_template('login.jinja2', **argv)
        return make_response(html)


# -----------------------------------------------------------------------------
# === Authentication ====
# -----------------------------------------------------------------------------


def do_verify():
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

    _info = {}
    for this in ['SAMLRequest', 'binding', 'RelayState']:
        if this not in query:
            raise BadRequest(f'Missing parameter {this} - please re-initiate login')
        _info[this] = unescape(query[this])
    _ticket = _get_ticket(_info, None)

    authn_ref = _ticket.saml_req.get_requested_authn_context()
    current_app.logger.debug(f'Authenticating with {repr(authn_ref)}')

    if not password or 'username' not in query:
        lox = f'{query["redirect_uri"]}?{_ticket.query_string}'
        current_app.logger.debug(f'Credentials not supplied. Redirect => {lox}')
        return redirect(lox)

    login_data = {
        'username': query['username'].strip(),
        'password': password,
    }
    del password  # keep out of any exception logs
    try:
        authninfo = current_app.authn.password_authn(login_data)
    except exceptions.EduidTooManyRequests as e:
        raise TooManyRequests(e.args[0])
    except exceptions.EduidForbidden as e:
        raise Forbidden(e.args[0])

    if not authninfo:
        current_app.logger.info(f'{_ticket.key}: Password authentication failed')
        _ticket.FailCount += 1
        session.sso_ticket = _ticket
        lox = f'{query["redirect_uri"]}?{_ticket.query_string}'
        current_app.logger.debug(f'Unknown user or wrong password. Redirect => {lox}')
        return redirect(lox)

    # Create SSO session
    if authninfo.user is None:
        raise RuntimeError('User not authenticated')
    user = authninfo.user
    current_app.logger.debug(f'User {user} authenticated OK (SAML id {repr(_ticket.saml_req.request_id)})')
    _sso_session = SSOSession(
        user_id=user.user_id, authn_request_id=_ticket.saml_req.request_id, authn_credentials=[authninfo],
    )

    # This session contains information about the fact that the user was authenticated. It is
    # used to avoid requiring subsequent authentication for the same user during a limited
    # period of time, by storing the session-id in a browser cookie.
    _session_id = current_app.sso_sessions.add_session(user.eppn, _sso_session)
    current_app.logger.debug(f'Created SSO session {repr(_session_id)}')

    # INFO-Log the request id (sha1 of SAMLrequest) and the sso_session
    current_app.logger.info(
        f'{_ticket.key}: login sso_session={_sso_session.public_id}, authn={authn_ref}, user={user}'
    )

    # Now that an SSO session has been created, redirect the users browser back to
    # the main entry point of the IdP (the 'redirect_uri'). The ticket reference `key'
    # is passed as an URL parameter instead of the SAMLRequest.
    session.sso_ticket = _ticket
    lox = query["redirect_uri"] + '?key=' + _ticket.key
    current_app.logger.debug(f'Redirecting user back to me => {lox}')
    resp = redirect(lox)
    # By base64-encoding this string, we should remain interoperable with the old CherryPy based IdP. Fingers crossed.
    b64_session_id = b64encode(_session_id)
    # For debugging purposes, save the IdP SSO cookie value in the common session as well.
    # This is because we think we might have issues overwriting cookies in redirect responses.
    session.idp.sso_cookie_val = b64_session_id
    return mischttp.set_sso_cookie(b64_session_id, resp)


def _update_ticket_samlrequest(ticket: SSOLoginData, binding: Optional[str]) -> None:
    try:
        ticket.saml_req = IdP_SAMLRequest(
            ticket.SAMLRequest, binding or ticket.binding, current_app.IDP, logger=None, debug=current_app.config.debug
        )
    except (SAMLParseError, SAMLValidationError):
        current_app.logger.exception('Failed updating SAML request in SSOLoginData (ticket)')
        raise BadRequest('Invalid login request. Try emptying browser cache and re-initiate login.')


# ----------------------------------------------------------------------------
def _get_ticket(info: Mapping[str, str], binding: Optional[str]) -> SSOLoginData:
    """
    Get the SSOLoginData from the eduid common session, or from query parameters.
    """
    logger = current_app.logger

    ticket: Optional[SSOLoginData] = session.sso_ticket
    if ticket:
        _update_ticket_samlrequest(ticket, binding)

    if not info:
        raise BadRequest('Bad request, please re-initiate login')
    _key = info.get('key')
    if not _key:
        if 'SAMLRequest' not in info:
            raise BadRequest('Missing SAMLRequest, please re-initiate login')
        _key = gen_key(info['SAMLRequest'])
        logger.debug(f"No 'key' in info, hashed SAMLRequest into key {_key}")

        if ticket and info['SAMLRequest'] != ticket.SAMLRequest:
            logger.debug('The SAMLRequest does not match the one in the ticket - invalidating ticket')
            session._sso_ticket = None  # work around sso_ticket setter that silently drops updated values
            ticket = session.sso_ticket = None

    if ticket and _key:
        # Validate that the key from `info' matches the one in the ticket.
        if _key != ticket.key:
            logger.debug('The `key` does not match the one in the ticket - invalidating ticket')
            session._sso_ticket = None  # work around sso_ticket setter that silently drops updated values
            ticket = session.sso_ticket = None

    if not ticket:
        # cache miss, parse SAMLRequest
        if binding is None:
            binding = info['binding']
        if binding is None:
            raise BadRequest('Bad request, no binding')
        assert _key  # please mypy
        ticket = _create_ticket(info, binding, _key)
        # Update the ticket in the eduid session after creating it
        # TODO: Remove this workaround in eduid-common when we only have one IdP code base to worry about
        session._sso_ticket = None  # work around sso_ticket setter that silently drops updated values
        session.sso_ticket = ticket

    return ticket


def _create_ticket(info: Mapping[str, str], binding: str, key: str) -> SSOLoginData:
    """
    Create an SSOLoginData instance from a dict.

    The dict must contain SAMLRequest and is typically

    {'RelayState': '/path',
     'SAMLRequest': 'nVLB...==',
     ...
    }

    :param info: dict containing at least `SAMLRequest' and `key'.
    :param binding: SAML2 binding as string (typically a URN)
    :returns: SSOLoginData instance
    """
    if not binding:
        raise InternalServerError('Can\'t create IdP ticket with unknown binding')
    ticket = SSOLoginData(
        key, info.get('SAMLRequest', ''), binding, info.get('RelayState', ''), int(info.get('FailCount', 0)),
    )
    if not ticket.SAMLRequest:
        current_app.logger.error(f'IdP ticket without SAML request: {ticket}')
        current_app.logger.error(f'Request info: {info}')
        current_app.logger.error(f'Binding: {binding}')
        current_app.logger.error(f'Key: {key}')
        raise InternalServerError('Can\'t create IdP ticket with no SAML request')
    _update_ticket_samlrequest(ticket, binding)

    current_app.logger.debug(f'Created new login state (IdP ticket) for request {key}')
    return ticket
