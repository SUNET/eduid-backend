# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import current_app, session
from xml.etree.ElementTree import ParseError
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.metadata import entity_descriptor
from saml2.client import Saml2Client
from saml2.response import SAMLError
from saml2.saml import AuthnContextClassRef
from saml2.samlp import RequestedAuthnContext

from eduid_common.authn.cache import OutstandingQueriesCache, IdentityCache
from eduid_common.authn.eduid_saml2 import BadSAMLResponse

__author__ = 'lundberg'


def create_authn_request(relay_state, selected_idp, required_loa, force_authn=False):

    kwargs = {
        "force_authn": str(force_authn).lower(),
    }

    # LOA
    current_app.logger.debug('Requesting AuthnContext {}'.format(required_loa))
    loa_uri = current_app.config['AUTHENTICATION_CONTEXT_MAP'][required_loa]
    requested_authn_context = RequestedAuthnContext(authn_context_class_ref=AuthnContextClassRef(text=loa_uri),
                                                    comparison='exact')
    kwargs['requested_authn_context'] = requested_authn_context

    client = Saml2Client(current_app.saml2_config)
    try:
        session_id, info = client.prepare_for_authenticate(entityid=selected_idp, relay_state=relay_state,
                                                           binding=BINDING_HTTP_REDIRECT, **kwargs)
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
        raise BadSAMLResponse(
            "SAML response has errors. Please check the logs")

    session_id = response.session_id()
    oq_cache.delete(session_id)
    return response


def create_metadata(config):
    return entity_descriptor(config)
