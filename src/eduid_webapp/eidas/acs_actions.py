# -*- coding: utf-8 -*-

from __future__ import absolute_import

import base64
from six.moves.urllib_parse import urlsplit, urlunsplit
from flask import current_app, redirect, request

from eduid_common.session import session
from eduid_common.authn.acs_registry import acs_action
from eduid_common.authn.eduid_saml2 import get_authn_ctx
from eduid_common.authn.utils import get_saml_attribute
from eduid_common.api.decorators import require_user
from eduid_common.api.utils import urlappend, save_and_sync_user, verify_relay_state
from eduid_common.api.helpers import verify_nin_for_user
from eduid_common.api.exceptions import AmTaskFailed, MsgTaskFailed
from eduid_userdb.proofing.user import ProofingUser
from eduid_userdb.proofing.state import NinProofingState, NinProofingElement
# TODO: Import FidoCredential in eduid_userdb.credential.__init__
from eduid_userdb.credentials.fido import FidoCredential
from eduid_userdb.logs import SwedenConnectProofing, MFATokenProofing

from eduid_webapp.eidas.helpers import is_required_loa, is_valid_reauthn, redirect_with_msg

__author__ = 'lundberg'


@acs_action('token-verify-action')
@require_user
def token_verify_action(session_info, user):
    """
    Use a Sweden Connect federation IdP assertion to verify a users MFA token and, if necessary,
    the users identity.

    :param session_info: the SAML session info
    :param user: Central db user

    :type session_info: dict
    :type user: eduid_userdb.User

    :return: redirect response
    :rtype: Response
    """
    redirect_url = urlappend(current_app.config['DASHBOARD_URL'], 'security')

    if not is_required_loa(session_info, 'loa3'):
        return redirect_with_msg(redirect_url, ':ERROR:eidas.authn_context_mismatch')

    if not is_valid_reauthn(session_info):
        return redirect_with_msg(redirect_url, ':ERROR:eidas.reauthn_expired')

    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    token_to_verify = proofing_user.credentials.filter(FidoCredential).find(
        session['verify_token_action_credential_id'])

    # Check (again) if token was used to authenticate this session
    if token_to_verify.key not in session['eduidIdPCredentialsUsed']:
        return redirect_with_msg(redirect_url, ':ERROR:eidas.token_not_in_credentials_used')

    # Verify asserted NIN for user if there are no verified NIN
    if proofing_user.nins.verified.count == 0:
        nin_verify_action(session_info)
        user = current_app.central_userdb.get_user_by_eppn(user.eppn)
        proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
        token_to_verify = proofing_user.credentials.filter(FidoCredential).find(
            session['verify_token_action_credential_id'])

    # Check that a verified NIN is equal to the asserted attribute personalIdentityNumber
    asserted_nin = get_saml_attribute(session_info, 'personalIdentityNumber')[0]
    user_nin = proofing_user.nins.verified.find(asserted_nin)
    if not user_nin:
        current_app.logger.error('Asserted NIN not matching user verified nins')
        current_app.logger.debug('Asserted NIN: {}'.format(asserted_nin))
        return redirect_with_msg(redirect_url, ':ERROR:eidas.nin_not_matching')

    # Create a proofing log
    issuer = session_info['issuer']
    current_app.logger.debug('Issuer: {}'.format(issuer))
    authn_context = get_authn_ctx(session_info)
    current_app.logger.debug('Authn context: {}'.format(authn_context))
    try:
        user_address = current_app.msg_relay.get_postal_address(user_nin.number)
    except MsgTaskFailed as e:
        current_app.logger.error('Navet lookup failed: {}'.format(e))
        current_app.stats.count('navet_error')
        return redirect_with_msg(redirect_url, ':ERROR:error_navet_task')
    proofing_log_entry = MFATokenProofing(user=proofing_user, created_by='eduid-eidas', nin=user_nin.number,
                                          issuer=issuer, authn_context_class=authn_context, key_id=token_to_verify.key,
                                          user_postal_address=user_address, proofing_version='2018v1')

    # Set token as verified
    token_to_verify.is_verified = True
    token_to_verify.proofing_method = 'SWAMID_AL2_MFA_HI'
    token_to_verify.proofing_version = '2018v1'

    # Save proofing log entry and save user
    if current_app.proofing_log.save(proofing_log_entry):
        current_app.logger.info('Recorded MFA token verification in the proofing log')
        try:
            save_and_sync_user(proofing_user)
        except AmTaskFailed as e:
            current_app.logger.error('Verifying token for user failed')
            current_app.logger.error('{}'.format(e))
            return redirect_with_msg(redirect_url, ':ERROR:Temporary technical problems')
        current_app.stats.count(name='fido_token_verified')

    return redirect_with_msg(redirect_url, 'eidas.token_verify_success')


@acs_action('nin-verify-action')
@require_user
def nin_verify_action(session_info, user):
    """
    Use a Sweden Connect federation IdP assertion to verify a users identity.

    :param session_info: the SAML session info
    :param user: Central db user

    :type session_info: dict
    :type user: eduid_userdb.User

    :return: redirect response
    :rtype: Response
    """
    redirect_url = urlappend(current_app.config['DASHBOARD_URL'], 'nins')

    if not is_required_loa(session_info, 'loa3'):
        return redirect_with_msg(redirect_url, ':ERROR:eidas.authn_context_mismatch')

    if not is_valid_reauthn(session_info):
        return redirect_with_msg(redirect_url, ':ERROR:eidas.reauthn_expired')

    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    asserted_nin = get_saml_attribute(session_info, 'personalIdentityNumber')[0]

    if proofing_user.nins.verified.count != 0:
        current_app.logger.error('User already has a verified NIN')
        current_app.logger.debug('Primary NIN: {}. Asserted NIN: {}'.format(proofing_user.nins.primary.number,
                                                                            asserted_nin))
        return redirect_with_msg(redirect_url, ':ERROR:eidas.nin_already_verified')

    # Create a proofing log
    issuer = session_info['issuer']
    authn_context = get_authn_ctx(session_info)
    try:
        user_address = current_app.msg_relay.get_postal_address(asserted_nin)
    except MsgTaskFailed as e:
        current_app.logger.error('Navet lookup failed: {}'.format(e))
        current_app.stats.count('navet_error')
        return redirect_with_msg(redirect_url, ':ERROR:error_navet_task')

    proofing_log_entry = SwedenConnectProofing(user=proofing_user, created_by='eduid-eidas', nin=asserted_nin,
                                               issuer=issuer, authn_context_class=authn_context,
                                               user_postal_address=user_address, proofing_version='2018v1')

    # Verify NIN for user
    try:
        nin_element = NinProofingElement(number=asserted_nin, application='eduid-eidas', verified=False)
        proofing_state = NinProofingState(id=None, modified_ts=None, eppn=user.eppn, nin=nin_element)
        verify_nin_for_user(user, proofing_state, proofing_log_entry)
    except AmTaskFailed as e:
        current_app.logger.error('Verifying NIN for user failed')
        current_app.logger.error('{}'.format(e))
        return redirect_with_msg(redirect_url, ':ERROR:Temporary technical problems')
    current_app.stats.count(name='nin_verified')

    return redirect_with_msg(redirect_url, 'eidas.nin_verify_success')


@acs_action('mfa-authentication-action')
@require_user
def mfa_authentication_action(session_info, user):
    relay_state = request.form.get('RelayState')
    current_app.logger.debug('RelayState: {}'.format(relay_state))
    redirect_url = None
    if 'eidas_redirect_urls' in session:
        redirect_url = session['eidas_redirect_urls'].pop(relay_state, None)
    if not redirect_url:
        # With no redirect url just redirect the user to dashboard for a new try to log in
        # TODO: This will result in a error 400 until we put the authentication in the session
        current_app.logger.error('Missing redirect url for mfa authentication')
        return redirect_with_msg(current_app.config['ACTION_URL'], ':ERROR:eidas.no_redirect_url')

    # We get the mfa authentication views "next" argument as base64 to avoid our request sanitation
    # to replace all & to &amp;
    redirect_url = base64.b64decode(redirect_url).decode('utf-8')
    # TODO: Rename verify_relay_state to verify_redirect_url
    redirect_url = verify_relay_state(redirect_url)

    if not is_required_loa(session_info, 'loa3'):
        return redirect_with_msg(redirect_url, ':ERROR:eidas.authn_context_mismatch')

    if not is_valid_reauthn(session_info):
        return redirect_with_msg(redirect_url, ':ERROR:eidas.reauthn_expired')

    # Check that a verified NIN is equal to the asserted attribute personalIdentityNumber
    asserted_nin = get_saml_attribute(session_info, 'personalIdentityNumber')[0]
    user_nin = user.nins.verified.find(asserted_nin)
    if not user_nin:
        current_app.logger.error('Asserted NIN not matching user verified nins')
        current_app.logger.debug('Asserted NIN: {}'.format(asserted_nin))
        return redirect_with_msg(redirect_url, ':ERROR:eidas.nin_not_matching')

    session.mfa_action.success = True
    session.mfa_action.issuer = session_info['issuer']
    session.mfa_action.authn_instant = session_info['authn_info'][0][2]
    session.mfa_action.authn_context = get_authn_ctx(session_info)

    # Redirect back to action app but to the redirect-action view
    resp = redirect_with_msg(redirect_url, 'actions.action-completed')
    scheme, netloc, path, query_string, fragment = urlsplit(resp.location)
    new_path = urlappend(path, 'redirect-action')
    new_url = urlunsplit((scheme, netloc, new_path, query_string, fragment))
    current_app.logger.debug(f'Redirecting to: {new_url}')
    return redirect(new_url)
