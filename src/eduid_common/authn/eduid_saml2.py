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
from typing import Mapping
from xml.etree.ElementTree import ParseError

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.response import UnsolicitedResponse

from .cache import IdentityCache, OutstandingQueriesCache
from .utils import SPConfig, get_saml_attribute
from eduid_common.session import EduidSession

logger = logging.getLogger(__name__)


class BadSAMLResponse(Exception):
    """Bad SAML response"""


def get_authn_ctx(session_info):
    """
    Get the SAML2 AuthnContext of the currently logged in users session.

    session_info is a dict like

        {'authn_info': [('http://www.swamid.se/policy/assurance/al1',
                    ['https://dev.idp.eduid.se/idp.xml'])],
         ...
        }

    :param session_info: The SAML2 session_info
    :return: The first AuthnContext
    :rtype: string | None
    """
    try:
        return session_info['authn_info'][0][0]
    except KeyError:
        return None


def get_authn_request(
    saml2_config: SPConfig, session, came_from, selected_idp, force_authn=False, sign_alg=None, digest_alg=None
):
    kwargs = {
        "force_authn": str(force_authn).lower(),
    }
    # Authn algorithms
    if sign_alg:
        kwargs['sign_alg'] = sign_alg
    if digest_alg:
        kwargs['digest_alg'] = digest_alg
    logger.debug(f'Authn request args: {kwargs}')

    client = Saml2Client(saml2_config)

    try:
        (session_id, info) = client.prepare_for_authenticate(
            entityid=selected_idp, relay_state=came_from, binding=BINDING_HTTP_REDIRECT, **kwargs
        )
    except TypeError:
        logger.error('Unable to know which IdP to use')
        raise

    oq_cache = OutstandingQueriesCache(session)
    oq_cache.set(session_id, came_from)
    return info


def get_authn_response(saml2_config: SPConfig, session: EduidSession, raw_response) -> Mapping:
    """
    Check a SAML response and return the 'session_info' pysaml2 dict.

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
    client = Saml2Client(saml2_config, identity_cache=IdentityCache(session))

    oq_cache = OutstandingQueriesCache(session)
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
        logger.error('SAML response is not correctly formatted: {!r}'.format(e))
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

    if response is None:
        logger.error('SAML response is None')
        raise BadSAMLResponse("SAML response has errors. Please check the logs")

    session_id = response.session_id()
    oq_cache.delete(session_id)
    session_info = response.session_info()

    logger.debug('Session info:\n{!s}\n\n'.format(pprint.pformat(session_info)))

    return session_info


def authenticate(app, session_info):
    """
    Locate a user using the identity found in the SAML assertion.

    :param request: Request object
    :param session_info: Session info received by pysaml2 client

    :returns: User

    :type request: Request()
    :type session_info: dict()
    :rtype: User or None
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
    strip_suffix = app.config.get('SAML2_STRIP_SAML_USER_SUFFIX', '')
    if strip_suffix:
        if saml_user.endswith(strip_suffix):
            saml_user = saml_user[: -len(strip_suffix)]

    logger.debug('Looking for user with eduPersonPrincipalName == {!r}'.format(saml_user))
    try:
        user = app.central_userdb.get_user_by_eppn(saml_user)
    except app.central_userdb.exceptions.UserDoesNotExist:
        logger.error('No user with eduPersonPrincipalName = {!r} found'.format(saml_user))
    except app.central_userdb.exceptions.MultipleUsersReturned:
        logger.error("There are more than one user with eduPersonPrincipalName = {!r}".format(saml_user))
    else:
        return user
    return None
