# -*- coding: utf-8 -*-

import logging

from dateutil.parser import parse as dt_parse
from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.metadata import entity_descriptor
from saml2.request import AuthnRequest
from saml2.saml import AuthnContextClassRef
from saml2.samlp import RequestedAuthnContext

from eduid.common.misc.timeutil import utc_now
from eduid.webapp.common.authn.cache import OutstandingQueriesCache
from eduid.webapp.common.authn.eduid_saml2 import get_authn_ctx
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import AuthnRequestRef
from eduid.webapp.eidas.app import current_eidas_app as current_app

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


def create_authn_request(
    authn_ref: AuthnRequestRef, selected_idp: str, required_loa: str, force_authn: bool = False
) -> AuthnRequest:

    kwargs = {
        "force_authn": str(force_authn).lower(),
    }

    # LOA
    logger.debug('Requesting AuthnContext {}'.format(required_loa))
    loa_uri = current_app.conf.authentication_context_map[required_loa]
    requested_authn_context = RequestedAuthnContext(
        authn_context_class_ref=AuthnContextClassRef(text=loa_uri), comparison='exact'
    )
    kwargs['requested_authn_context'] = requested_authn_context

    client = Saml2Client(current_app.saml2_config)
    try:
        session_id, info = client.prepare_for_authenticate(
            entityid=selected_idp,
            relay_state=authn_ref,
            binding=BINDING_HTTP_REDIRECT,
            sigalg=current_app.conf.authn_sign_alg,
            digest_alg=current_app.conf.authn_digest_alg,
            **kwargs,
        )
    except TypeError:
        logger.error('Unable to know which IdP to use')
        raise

    oq_cache = OutstandingQueriesCache(session.eidas.sp.pysaml2_dicts)
    oq_cache.set(session_id, authn_ref)
    return info


def is_required_loa(session_info: SessionInfo, required_loa: str) -> bool:
    authn_context = get_authn_ctx(session_info)
    loa_uri = current_app.conf.authentication_context_map[required_loa]
    if authn_context == loa_uri:
        return True
    logger.error('Asserted authn context class does not match required class')
    logger.error(f'Asserted: {authn_context}')
    logger.error(f'Required: {loa_uri}')
    return False


def is_valid_reauthn(session_info: SessionInfo, max_age: int = 60) -> bool:
    """
    :param session_info: The SAML2 session_info
    :param max_age: Max time (in seconds) since authn that is to be allowed
    :return: True if authn instant is no older than max_age
    """
    now = utc_now()
    authn_instant = dt_parse(session_info['authn_info'][0][2])
    age = now - authn_instant
    if age.total_seconds() <= max_age:
        logger.debug(f'Re-authn is valid, authn instant {authn_instant}, age {age}, max_age {max_age}s')
        return True
    logger.error(f'Authn instant {authn_instant} too old (age {age}, max_age {max_age} seconds)')
    return False


def create_metadata(config):
    return entity_descriptor(config)


def staging_nin_remap(session_info: SessionInfo) -> SessionInfo:
    """
    Remap from known test nins to users correct nins.

    :param session_info: the SAML session info
    :return: SAML session info with new nin mapped
    """
    attributes = session_info['ava']
    asserted_test_nin = attributes['personalIdentityNumber'][0]
    user_nin = current_app.conf.staging_nin_map.get(asserted_test_nin, None)
    if user_nin:
        attributes['personalIdentityNumber'] = [user_nin]
    return session_info
