#
# Copyright (c) 2015 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

import logging
import pprint
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple, Union
from xml.etree.ElementTree import ParseError

from dateutil.parser import parse as dt_parse
from flask import abort, make_response, redirect, request

from eduid.userdb.element import ElementKey
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.ident import decode
from saml2.response import AuthnResponse, LogoutResponse, StatusError, UnsolicitedResponse
from werkzeug.exceptions import Forbidden
from werkzeug.wrappers import Response
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.userdb import UserDB
from eduid.userdb.exceptions import MultipleUsersReturned, UserDoesNotExist
from eduid.userdb.user import User
from eduid.webapp.authn.app import current_authn_app as current_app
from eduid.webapp.common.api.utils import sanitise_redirect_url
from eduid.webapp.common.authn.cache import IdentityCache, OutstandingQueriesCache, StateCache
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.authn.utils import SPConfig, get_saml_attribute
from eduid.webapp.common.session import EduidSession, session
from eduid.webapp.common.session.namespaces import AuthnRequestRef, SP_AuthnRequest, SPAuthnData

logger = logging.getLogger(__name__)


class BadSAMLResponse(Exception):
    """Bad SAML response"""


def get_authn_ctx(session_info: SessionInfo) -> Optional[str]:
    """
    Get the SAML2 AuthnContext of the currently logged in users session.

    session_info is a dict like

        {'authn_info': [('http://www.swamid.se/policy/assurance/al1',
                    ['https://dev.idp.eduid.se/idp.xml'])],
         ...
        }

    :param session_info: The SAML2 session_info
    :return: The first AuthnContext
    """
    try:
        return session_info['authn_info'][0][0]
    except KeyError:
        return None


def get_authn_request(
    saml2_config: SPConfig,
    session: EduidSession,
    relay_state: str,
    authn_id: AuthnRequestRef,
    selected_idp: Optional[str],
    force_authn: bool = False,
    sign_alg: Optional[str] = None,
    digest_alg: Optional[str] = None,
):
    kwargs = {
        'force_authn': str(force_authn).lower(),
    }
    logger.debug(f'Authn request args: {kwargs}')

    client = Saml2Client(saml2_config)

    try:
        (session_id, info) = client.prepare_for_authenticate(
            entityid=selected_idp,
            relay_state=relay_state,
            binding=BINDING_HTTP_REDIRECT,
            sigalg=sign_alg,
            digest_alg=digest_alg,
            **kwargs,
        )
    except TypeError:
        logger.error('Unable to know which IdP to use')
        raise

    oq_cache = OutstandingQueriesCache(session.authn.sp.pysaml2_dicts)
    oq_cache.set(session_id, authn_id)
    return info


def get_authn_response(
    saml2_config: SPConfig, sp_data: SPAuthnData, session: EduidSession, raw_response: str
) -> Tuple[AuthnResponse, AuthnRequestRef]:
    """
    Check a SAML response and return the the response.

    The response can be used to retrieve a session_info dict.

    Example session_info:

    {'authn_info': [('urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport', [],
                     '2019-06-17T00:00:01Z')],
     'ava': {'eduPersonPrincipalName': ['eppn@eduid.se'],
             'eduidIdPCredentialsUsed': ['...']},
     'came_from': 'https://dashboard.eduid.se/profile/personaldata',
     'issuer': 'https://login.idp.eduid.se/idp.xml',
     'name_id': <saml2.saml.NameID object>,
     'not_on_or_after': 156000000,
     'session_index': 'id-foo'}
    """
    client = Saml2Client(saml2_config, identity_cache=IdentityCache(sp_data.pysaml2_dicts))

    oq_cache = OutstandingQueriesCache(sp_data.pysaml2_dicts)
    outstanding_queries = oq_cache.outstanding_queries()

    try:
        # process the authentication response
        response = client.parse_authn_request_response(raw_response, BINDING_HTTP_POST, outstanding_queries)
    except AssertionError:
        logger.error('SAML response is not verified')
        raise BadSAMLResponse(
            """SAML response is not verified. May be caused by the response
            was not issued at a reasonable time or the SAML status is not ok.
            Check the IDP datetime setup"""
        )
    except ParseError as e:
        logger.error(f'SAML response is not correctly formatted: {repr(e)}')
        raise BadSAMLResponse(
            """SAML response is not correctly formatted and therefore the
            XML document could not be parsed.
            """
        )
    except UnsolicitedResponse as e:
        logger.exception('Unsolicited SAML response')
        # Extra debug to try and find the cause for some of these that seem to be incorrect
        logger.debug(f'Session: {session}')
        logger.debug(f'Outstanding queries cache: {oq_cache}')
        logger.debug(f'Outstanding queries: {outstanding_queries}')
        raise e
    except StatusError as e:
        logger.error(f'SAML response was a failure: {repr(e)}')
        raise BadSAMLResponse(f'SAML response was a failure')

    if response is None:
        logger.error('SAML response is None')
        raise BadSAMLResponse('SAML response has errors')

    session_id = response.session_id()
    oq_cache.delete(session_id)

    authn_reqref = outstanding_queries[session_id]
    logger.debug(
        f'Response {session_id}, request reference {authn_reqref}\n'
        f'session info:\n{pprint.pformat(response.session_info())}\n\n'
    )

    return response, authn_reqref


def authenticate(session_info: SessionInfo, strip_suffix: Optional[str], userdb: UserDB) -> Optional[User]:
    """
    Locate a user using the identity found in the SAML assertion.

    :param session_info: Session info received by pysaml2 client
    :param strip_suffix: SAML scope to strip from the end of the eppn
    :param userdb: In what database to look for the user

    :returns: User, if found
    """
    if session_info is None:
        raise TypeError('Session info is None')

    attribute_values = get_saml_attribute(session_info, 'eduPersonPrincipalName')
    if not attribute_values:
        logger.error('Could not find attribute eduPersonPrincipalName in the SAML assertion')
        return None

    saml_user = attribute_values[0]

    # eduPersonPrincipalName might be scoped and the scope (e.g. "@example.com")
    # might have to be removed before looking for the user in the database.
    if strip_suffix:
        if saml_user.endswith(strip_suffix):
            saml_user = saml_user[: -len(strip_suffix)]

    logger.debug(f'Looking for user with eduPersonPrincipalName == {repr(saml_user)}')
    try:
        return userdb.get_user_by_eppn(saml_user)
    except UserDoesNotExist:
        logger.error(f'No user with eduPersonPrincipalName = {repr(saml_user)} found')
    except MultipleUsersReturned:
        logger.error(f'There are more than one user with eduPersonPrincipalName == {repr(saml_user)}')
    return None


def saml_logout(sp_config: SPConfig, user: User, location: str) -> Response:
    """
    SAML Logout Request initiator.
    This function initiates the SAML2 Logout request
    using the pysaml2 library to create the LogoutRequest.
    """
    if not session.authn.name_id:
        logger.warning(f'The session does not contain the subject id for user {user}')
        session.invalidate()
        logger.info(f'Invalidated session for {user}')
        logger.info(f'Redirection user to {location} for logout')
        return redirect(location)

    # Since we have a subject_id, call the IdP using SOAP to do a global logout

    state = StateCache(session.authn.sp.pysaml2_dicts)  # _saml2_state in the session
    identity = IdentityCache(session.authn.sp.pysaml2_dicts)  # _saml2_identities in the session
    client = Saml2Client(sp_config, state_cache=state, identity_cache=identity)

    _subject_id = decode(session.authn.name_id)
    logger.info(f'Initiating global logout for {_subject_id}')
    logouts = client.global_logout(_subject_id)
    logger.debug(f'Logout response: {logouts}')

    # Invalidate session, now that Saml2Client is done with the information within.
    session.invalidate()
    logger.info(f'Invalidated session for {user}')

    loresponse = list(logouts.values())[0]
    # loresponse is a dict for REDIRECT binding, and LogoutResponse for SOAP binding
    if isinstance(loresponse, LogoutResponse):
        if loresponse.status_ok():
            location = sanitise_redirect_url(request.form.get('RelayState', location), location)
            return redirect(location)
        else:
            logger.error(f'The logout response was not OK: {loresponse}')
            abort(500)

    headers_tuple = loresponse[1]['headers']
    location = headers_tuple[0][1]
    logger.info(f'Redirecting {user} to {location} after successful logout')
    return redirect(location)


@dataclass
class AssertionData:
    session_info: SessionInfo
    user: Optional[User]
    authndata: SP_AuthnRequest

    def __str__(self) -> str:
        return (
            f'<{self.__class__.__name__}: user={self.user}, authndata={self.authndata}, '
            f'session_info={self.session_info}>'
        )


def process_assertion(
    form: Mapping[str, Any],
    sp_data: SPAuthnData,
    error_redirect_url: str,
    strip_suffix: Optional[str] = None,
    authenticate_user: bool = True,
) -> Union[AssertionData, WerkzeugResponse]:
    """
    Common code for our various SAML SPs (currently authn and eidas) to process a received SAML assertion.

    If the IdP is our own, we load the list of credentials used for this particular authentication and
    put that in the result. This way, token vetting applications can know that a particular token was
    used for authentication when they request re-authn.
    """
    if 'SAMLResponse' not in form:
        abort(400)

    saml_response = form['SAMLResponse']
    try:
        response, authn_ref = get_authn_response(current_app.saml2_config, sp_data, session, saml_response)
    except BadSAMLResponse as e:
        current_app.logger.error(f'BadSAMLResponse: {e}')
        return make_response(str(e), 400)

    if authn_ref not in sp_data.authns:
        current_app.logger.info(f'Unknown response. Redirecting user to {error_redirect_url}')
        return redirect(error_redirect_url)

    authn_data = sp_data.authns[authn_ref]
    current_app.logger.debug(f'Authentication request data retrieved from session: {authn_data}')

    session_info = response.session_info()
    authn_data.authn_instant = dt_parse(session_info['authn_info'][0][2])

    user = None
    if authenticate_user:
        current_app.logger.debug('Trying to locate the user authenticated by the IdP')
        user = authenticate(session_info, strip_suffix=strip_suffix, userdb=current_app.central_userdb)
        if user is None:
            current_app.logger.error('Could not find the user identified by the IdP')
            raise Forbidden('Access not authorized')

        credentials_used = get_saml_attribute(session_info, 'eduidIdPCredentialsUsed')
        if credentials_used:
            for cred_used in credentials_used:
                this = user.credentials.find(ElementKey(cred_used))
                if not this:
                    current_app.logger.warning(f'Could not find credential with key {cred_used} on user {user}')
                    continue
                authn_data.credentials_used += [this.key]

    return AssertionData(session_info=session_info, user=user, authndata=authn_data)
