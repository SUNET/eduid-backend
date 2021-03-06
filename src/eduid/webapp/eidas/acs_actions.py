# -*- coding: utf-8 -*-


import base64
from enum import Enum, unique
from typing import Any, Mapping

from flask import redirect, request
from six.moves.urllib_parse import urlsplit, urlunsplit
from werkzeug.wrappers import Response as WerkzeugResponse

# TODO: Import FidoCredential in eduid.userdb.credential.__init__
from eduid.userdb import User
from eduid.userdb.credentials.fido import FidoCredential
from eduid.userdb.logs import MFATokenProofing, SwedenConnectProofing
from eduid.userdb.proofing.state import NinProofingElement, NinProofingState
from eduid.userdb.proofing.user import ProofingUser
from eduid.webapp.common.api.decorators import require_user
from eduid.webapp.common.api.exceptions import AmTaskFailed, MsgTaskFailed
from eduid.webapp.common.api.helpers import verify_nin_for_user
from eduid.webapp.common.api.messages import CommonMsg, redirect_with_msg
from eduid.webapp.common.api.utils import save_and_sync_user, urlappend, verify_relay_state
from eduid.webapp.common.authn.acs_registry import acs_action
from eduid.webapp.common.authn.eduid_saml2 import SessionInfo, get_authn_ctx
from eduid.webapp.common.authn.utils import get_saml_attribute
from eduid.webapp.common.session import session
from eduid.webapp.eidas.app import current_eidas_app as current_app
from eduid.webapp.eidas.helpers import EidasMsg, is_required_loa, is_valid_reauthn

__author__ = 'lundberg'


@unique
class EidasAcsAction(Enum):
    token_verify = 'token-verify-action'
    nin_verify = 'nin-verify-action'
    mfa_authn = 'mfa-authentication-action'


@acs_action(EidasAcsAction.token_verify)
@require_user
def token_verify_action(session_info: SessionInfo, user: User) -> WerkzeugResponse:
    """
    Use a Sweden Connect federation IdP assertion to verify a users MFA token and, if necessary,
    the users identity.

    :param session_info: the SAML session info
    :param user: Central db user

    :return: redirect response
    """
    redirect_url = current_app.conf.token_verify_redirect_url

    if not is_required_loa(session_info, 'loa3'):
        return redirect_with_msg(redirect_url, EidasMsg.authn_context_mismatch)

    if not is_valid_reauthn(session_info):
        return redirect_with_msg(redirect_url, EidasMsg.reauthn_expired)

    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    token_to_verify = proofing_user.credentials.filter(FidoCredential).find(
        session['verify_token_action_credential_id']
    )

    # Check (again) if token was used to authenticate this session
    if token_to_verify.key not in session['eduidIdPCredentialsUsed']:
        return redirect_with_msg(redirect_url, EidasMsg.token_not_in_creds)

    # Verify asserted NIN for user if there are no verified NIN
    if proofing_user.nins.verified.count == 0:
        nin_verify_action(session_info)
        user = current_app.central_userdb.get_user_by_eppn(user.eppn)
        proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
        token_to_verify = proofing_user.credentials.filter(FidoCredential).find(
            session['verify_token_action_credential_id']
        )

    # Check that a verified NIN is equal to the asserted attribute personalIdentityNumber
    _nin_list = get_saml_attribute(session_info, 'personalIdentityNumber')

    if _nin_list is None:
        raise ValueError("Missing PIN in SAML session info")

    asserted_nin = _nin_list[0]
    user_nin = proofing_user.nins.verified.find(asserted_nin)
    if not user_nin:
        current_app.logger.error('Asserted NIN not matching user verified nins')
        current_app.logger.debug('Asserted NIN: {}'.format(asserted_nin))
        return redirect_with_msg(redirect_url, EidasMsg.nin_not_matching)

    # Create a proofing log
    issuer = session_info['issuer']
    current_app.logger.debug('Issuer: {}'.format(issuer))
    authn_context = get_authn_ctx(session_info)
    if not authn_context:
        current_app.logger.error('No authn context in session_info')
        return redirect_with_msg(redirect_url, EidasMsg.authn_context_mismatch)

    current_app.logger.debug('Authn context: {}'.format(authn_context))
    try:
        user_address = current_app.msg_relay.get_postal_address(user_nin.number)
    except MsgTaskFailed as e:
        current_app.logger.error('Navet lookup failed: {}'.format(e))
        current_app.stats.count('navet_error')
        return redirect_with_msg(redirect_url, CommonMsg.navet_error)
    proofing_log_entry = MFATokenProofing(
        eppn=proofing_user.eppn,
        created_by='eduid-eidas',
        nin=user_nin.number,
        issuer=issuer,
        authn_context_class=authn_context,
        key_id=token_to_verify.key,
        user_postal_address=user_address,
        proofing_version='2018v1',
    )

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
            return redirect_with_msg(redirect_url, CommonMsg.temp_problem)
        current_app.stats.count(name='fido_token_verified')

    return redirect_with_msg(redirect_url, EidasMsg.verify_success, error=False)


@acs_action(EidasAcsAction.nin_verify)
@require_user
def nin_verify_action(session_info: SessionInfo, user: User) -> WerkzeugResponse:
    """
    Use a Sweden Connect federation IdP assertion to verify a users identity.

    :param session_info: the SAML session info
    :param user: Central db user

    :return: redirect response
    """

    redirect_url = current_app.conf.nin_verify_redirect_url

    if not is_required_loa(session_info, 'loa3'):
        return redirect_with_msg(redirect_url, EidasMsg.authn_context_mismatch)

    if not is_valid_reauthn(session_info):
        return redirect_with_msg(redirect_url, EidasMsg.reauthn_expired)

    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    _nin_list = get_saml_attribute(session_info, 'personalIdentityNumber')

    if _nin_list is None:
        raise ValueError("Missing PIN in SAML session info")

    asserted_nin = _nin_list[0]

    if proofing_user.nins.verified.count != 0:
        current_app.logger.error('User already has a verified NIN')
        current_app.logger.debug(
            'Primary NIN: {}. Asserted NIN: {}'.format(proofing_user.nins.primary.number, asserted_nin)
        )
        return redirect_with_msg(redirect_url, EidasMsg.nin_already_verified)

    # Create a proofing log
    issuer = session_info['issuer']
    authn_context = get_authn_ctx(session_info)
    if not authn_context:
        current_app.logger.error('No authn context in session_info')
        return redirect_with_msg(redirect_url, EidasMsg.authn_context_mismatch)

    try:
        user_address = current_app.msg_relay.get_postal_address(asserted_nin)
    except MsgTaskFailed as e:
        current_app.logger.error('Navet lookup failed: {}'.format(e))
        current_app.stats.count('navet_error')
        return redirect_with_msg(redirect_url, CommonMsg.navet_error)

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
        proofing_state = NinProofingState(id=None, modified_ts=None, eppn=user.eppn, nin=nin_element)
        if not verify_nin_for_user(user, proofing_state, proofing_log_entry):
            current_app.logger.error(f'Failed verifying NIN for user {user}')
            return redirect_with_msg(redirect_url, CommonMsg.temp_problem)
    except AmTaskFailed:
        current_app.logger.exception('Verifying NIN for user failed')
        return redirect_with_msg(redirect_url, CommonMsg.temp_problem)
    current_app.stats.count(name='nin_verified')

    return redirect_with_msg(redirect_url, EidasMsg.nin_verify_success, error=False)


@require_user
def nin_verify_BACKDOOR(user: User) -> WerkzeugResponse:
    """
    Mock using a Sweden Connect federation IdP assertion to verify a users identity
    when the request carries a magic cookie.

    :param user: Central db user

    :return: redirect response
    """

    redirect_url = current_app.conf.nin_verify_redirect_url

    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    asserted_nin = request.cookies.get('nin')

    if asserted_nin is None:
        raise RuntimeError("No backdoor without a NIN in a cookie")

    if proofing_user.nins.verified.count != 0:
        current_app.logger.error('User already has a verified NIN')
        current_app.logger.debug(
            'Primary NIN: {}. Asserted NIN: {}'.format(proofing_user.nins.primary.number, asserted_nin)
        )
        return redirect_with_msg(redirect_url, ':ERROR:eidas.nin_already_verified')

    # Create a proofing log
    issuer = 'https://idp.example.com/simplesaml/saml2/idp/metadata.php'
    authn_context = 'http://id.elegnamnden.se/loa/1.0/loa3'

    user_address = {
        'Name': {'GivenNameMarking': '20', 'GivenName': 'Magic Cookie', 'Surname': 'Testsson'},
        'OfficialAddress': {'Address2': 'MAGIC COOKIE', 'PostalCode': '12345', 'City': 'LANDET'},
    }

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
        proofing_state = NinProofingState(id=None, modified_ts=None, eppn=user.eppn, nin=nin_element)
        if not verify_nin_for_user(user, proofing_state, proofing_log_entry):
            current_app.logger.error(f'Failed verifying NIN for user {user}')
            return redirect_with_msg(redirect_url, ':ERROR:Temporary technical problems')
    except AmTaskFailed:
        current_app.logger.exception('Verifying NIN for user failed')
        return redirect_with_msg(redirect_url, ':ERROR:Temporary technical problems')
    current_app.stats.count(name='nin_verified')

    return redirect_with_msg(redirect_url, 'eidas.nin_verify_success')


@acs_action(EidasAcsAction.mfa_authn)
@require_user
def mfa_authentication_action(session_info: SessionInfo, user: User) -> WerkzeugResponse:
    relay_state = request.form.get('RelayState')
    current_app.logger.debug('RelayState: {}'.format(relay_state))
    redirect_url = None
    if 'eidas_redirect_urls' in session:
        redirect_url = session['eidas_redirect_urls'].pop(relay_state, None)
    if not redirect_url:
        # With no redirect url just redirect the user to dashboard for a new try to log in
        # TODO: This will result in a error 400 until we put the authentication in the session
        current_app.logger.error('Missing redirect url for mfa authentication')
        return redirect_with_msg(current_app.conf.action_url, EidasMsg.no_redirect_url)

    # We get the mfa authentication views "next" argument as base64 to avoid our request sanitation
    # to replace all & to &amp;
    redirect_url = base64.b64decode(redirect_url).decode('utf-8')
    # TODO: Rename verify_relay_state to verify_redirect_url
    redirect_url = verify_relay_state(redirect_url)

    if not is_required_loa(session_info, 'loa3'):
        return redirect_with_msg(redirect_url, EidasMsg.authn_context_mismatch)

    if not is_valid_reauthn(session_info):
        return redirect_with_msg(redirect_url, EidasMsg.reauthn_expired)

    # Check that a verified NIN is equal to the asserted attribute personalIdentityNumber
    _personal_idns = get_saml_attribute(session_info, 'personalIdentityNumber')
    if _personal_idns is None:
        current_app.logger.error(
            'Got no personalIdentityNumber attributes. pysaml2 without the right attribute_converter?'
        )
        # TODO: change to reasonable redirect_with_msg when the ENUM work for that is merged
        raise RuntimeError('Got no personalIdentityNumber')

    asserted_nin = _personal_idns[0]
    user_nin = user.nins.verified.find(asserted_nin)
    if not user_nin:
        current_app.logger.error('Asserted NIN not matching user verified nins')
        current_app.logger.debug('Asserted NIN: {}'.format(asserted_nin))
        current_app.stats.count(name='mfa_auth_nin_not_matching')
        return redirect_with_msg(redirect_url, EidasMsg.nin_not_matching)

    if session.mfa_action is None:
        # TODO: change to reasonable redirect_with_msg? This should not happen...
        raise RuntimeError('No MFA info in the session')

    session.mfa_action.success = True
    session.mfa_action.issuer = session_info['issuer']
    session.mfa_action.authn_instant = session_info['authn_info'][0][2]
    session.mfa_action.authn_context = get_authn_ctx(session_info)
    current_app.stats.count(name='mfa_auth_success')
    current_app.stats.count(name=f'mfa_auth_{session_info["issuer"]}_success')

    # Redirect back to action app but to the redirect-action view
    resp = redirect_with_msg(redirect_url, EidasMsg.action_completed, error=False)
    parsed_url = urlsplit(str(resp.location))
    new_path = urlappend(str(parsed_url.path), 'redirect-action')
    parsed_url = parsed_url._replace(path=new_path)
    new_url = urlunsplit(parsed_url)
    current_app.logger.debug(f'Redirecting to: {new_url}')
    return redirect(new_url)
