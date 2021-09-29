# -*- coding: utf-8 -*-

import logging
from enum import unique
from typing import Optional

from dateutil.parser import parse as dt_parse
from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.metadata import entity_descriptor
from saml2.request import AuthnRequest
from saml2.saml import AuthnContextClassRef
from saml2.samlp import RequestedAuthnContext

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.logs import SwedenConnectProofing
from eduid.userdb.proofing import NinProofingElement, ProofingUser
from eduid.userdb.proofing.state import NinProofingState
from eduid.webapp.common.api.exceptions import AmTaskFailed, MsgTaskFailed
from eduid.webapp.common.api.helpers import verify_nin_for_user
from eduid.webapp.common.api.messages import CommonMsg, TranslatableMsg
from eduid.webapp.common.authn.cache import OutstandingQueriesCache
from eduid.webapp.common.authn.eduid_saml2 import get_authn_ctx
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.authn.utils import get_saml_attribute
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import AuthnRequestRef
from eduid.webapp.eidas.app import current_eidas_app as current_app

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


@unique
class EidasMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # LOA 3 not needed
    authn_context_mismatch = 'eidas.authn_context_mismatch'
    # re-authentication expired
    reauthn_expired = 'eidas.reauthn_expired'
    # the token was not used to authenticate this session
    token_not_in_creds = 'eidas.token_not_in_credentials_used'
    # the personalIdentityNumber from eidas does not correspond
    # to a verified nin in the user's account
    nin_not_matching = 'eidas.nin_not_matching'
    # successfully verified the token
    verify_success = 'eidas.token_verify_success'
    # The user already has a verified NIN
    nin_already_verified = 'eidas.nin_already_verified'
    # Successfully verified the NIN
    nin_verify_success = 'eidas.nin_verify_success'
    # missing redirect URL for mfa authn
    no_redirect_url = 'eidas.no_redirect_url'
    # Action completed, redirect to actions app
    action_completed = 'actions.action-completed'
    # Token not found on the credentials in the user's account
    token_not_found = 'eidas.token_not_found'


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


def verify_nin_from_external_mfa(proofing_user: ProofingUser, session_info: SessionInfo) -> Optional[TranslatableMsg]:

    _nin_list = get_saml_attribute(session_info, 'personalIdentityNumber')
    if _nin_list is None:
        raise ValueError("Missing NIN in SAML session info")
    asserted_nin = _nin_list[0]

    # Create a proofing log
    issuer = session_info['issuer']
    authn_context = get_authn_ctx(session_info)
    if not authn_context:
        current_app.logger.error('No authn context in session_info')
        return EidasMsg.authn_context_mismatch

    try:
        user_address = current_app.msg_relay.get_postal_address(asserted_nin)
    except MsgTaskFailed as e:
        current_app.logger.error('Navet lookup failed: {}'.format(e))
        current_app.stats.count('navet_error')
        return CommonMsg.navet_error

    proofing_log_entry = SwedenConnectProofing(
        eppn=proofing_user.eppn,
        created_by='eduid-eidas',
        nin=asserted_nin,
        issuer=issuer,
        authn_context_class=authn_context,
        user_postal_address=user_address,
        proofing_version='2018v1',
    )

    # Verify NIN for user
    try:
        nin_element = NinProofingElement(number=asserted_nin, created_by='eduid-eidas', is_verified=False)
        proofing_state = NinProofingState(id=None, modified_ts=None, eppn=proofing_user.eppn, nin=nin_element)
        if not verify_nin_for_user(proofing_user, proofing_state, proofing_log_entry):
            current_app.logger.error(f'Failed verifying NIN for user {proofing_user}')
            return CommonMsg.temp_problem
    except AmTaskFailed:
        current_app.logger.exception('Verifying NIN for user failed')
        return CommonMsg.temp_problem

    current_app.stats.count(name='nin_verified')
    return None


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
