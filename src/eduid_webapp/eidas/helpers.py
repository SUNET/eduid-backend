# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from xml.etree.ElementTree import ParseError

from dateutil.parser import parse as dt_parse
from dateutil.tz import tzutc
from flask import current_app, redirect
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid_common.authn.cache import IdentityCache, OutstandingQueriesCache
from eduid_common.authn.eduid_saml2 import BadSAMLResponse, get_authn_ctx
from eduid_common.session import session

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.metadata import entity_descriptor
from saml2.response import SAMLError
from saml2.saml import AuthnContextClassRef
from saml2.samlp import RequestedAuthnContext

__author__ = 'lundberg'


def create_authn_request(relay_state, selected_idp, required_loa, force_authn=False):

    kwargs = {
        "force_authn": str(force_authn).lower(),
    }

    # LOA
    current_app.logger.debug('Requesting AuthnContext {}'.format(required_loa))
    loa_uri = current_app.config.authentication_context_map[required_loa]
    requested_authn_context = RequestedAuthnContext(
        authn_context_class_ref=AuthnContextClassRef(text=loa_uri), comparison='exact'
    )
    kwargs['requested_authn_context'] = requested_authn_context

    # Authn algorithms
    kwargs['sign_alg'] = current_app.config.authn_sign_alg
    kwargs['digest_alg'] = current_app.config.authn_digest_alg

    client = Saml2Client(current_app.saml2_config)
    try:
        session_id, info = client.prepare_for_authenticate(
            entityid=selected_idp, relay_state=relay_state, binding=BINDING_HTTP_REDIRECT, **kwargs
        )
    except TypeError:
        current_app.logger.error('Unable to know which IdP to use')
        raise

    oq_cache = OutstandingQueriesCache(session)
    oq_cache.set(session_id, relay_state)
    return info


def parse_authn_response(saml_response):

    client = Saml2Client(current_app.saml2_config, identity_cache=IdentityCache(session))

    oq_cache = OutstandingQueriesCache(session)
    outstanding_queries = oq_cache.outstanding_queries()

    try:
        # process the authentication response
        response = client.parse_authn_request_response(saml_response, BINDING_HTTP_POST, outstanding_queries)
    except SAMLError as e:
        current_app.logger.error('SAML response is not verified: {}'.format(e))
        raise BadSAMLResponse(str(e))
    except ParseError as e:
        current_app.logger.error('SAML response is not correctly formatted: {}'.format(e))
        raise BadSAMLResponse('SAML response XML document could not be parsed: {}'.format(e))

    if response is None:
        current_app.logger.error('SAML response is None')
        raise BadSAMLResponse("SAML response has errors. Please check the logs")

    session_id = response.session_id()
    oq_cache.delete(session_id)
    return response


def is_required_loa(session_info, required_loa):
    authn_context = get_authn_ctx(session_info)
    loa_uri = current_app.config.authentication_context_map[required_loa]
    if authn_context == loa_uri:
        return True
    current_app.logger.error('Asserted authn context class does not match required class')
    current_app.logger.error('Asserted: {}'.format(authn_context))
    current_app.logger.error('Required: {}'.format(loa_uri))
    return False


def is_valid_reauthn(session_info, max_age=60) -> bool:
    """
    :param session_info: The SAML2 session_info
    :param max_age: Max time (in seconds) since authn
    :return: True if authn instant is no older than max_age
    :rtype: bool
    """
    utc_tz = tzutc()
    authn_instant = dt_parse(session_info['authn_info'][0][2])
    max_age = timedelta(seconds=max_age)
    if authn_instant >= (datetime.now(tz=utc_tz) - max_age):
        return True
    current_app.logger.error('Asserted authn instant was older than required')
    current_app.logger.error('Authn instant: {}'.format(authn_instant))
    current_app.logger.error('Oldest accepted: {}'.format(datetime.utcnow() + max_age))
    return False


def create_metadata(config):
    return entity_descriptor(config)


def redirect_with_msg(url: str, msg: str) -> WerkzeugResponse:
    """
    :param url: URL to redirect to
    :param msg: message to append to query string
    :return: Redirect response with appended query string message
    """
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    query_list = parse_qsl(query_string)
    query_list.append(('msg', msg))
    new_query_string = urlencode(query_list)
    return redirect(urlunsplit((scheme, netloc, path, new_query_string, fragment)))


def staging_nin_remap(session_info):
    """
    Remap from known test nins to users correct nins.

    :param session_info: the SAML session info
    :type session_info: dict
    :return: SAML session info with new nin mapped
    :rtype: dict
    """
    attributes = session_info['ava']
    asserted_test_nin = attributes['personalIdentityNumber'][0]
    user_nin = current_app.config.staging_nin_map.get(asserted_test_nin, None)
    if user_nin:
        attributes['personalIdentityNumber'] = [user_nin]
    return session_info
