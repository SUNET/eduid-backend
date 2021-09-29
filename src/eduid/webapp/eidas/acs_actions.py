# -*- coding: utf-8 -*-


from typing import Optional

from flask import request
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.userdb import User, LockedIdentityNin
from eduid.userdb.credentials.fido import FidoCredential
from eduid.userdb.logs import MFATokenProofing, SwedenConnectProofing
from eduid.userdb.proofing.state import NinProofingElement, NinProofingState
from eduid.userdb.proofing.user import ProofingUser
from eduid.webapp.authn.helpers import credential_used_to_authenticate
from eduid.webapp.common.api.decorators import require_user
from eduid.webapp.common.api.exceptions import AmTaskFailed, MsgTaskFailed
from eduid.webapp.common.api.helpers import verify_nin_for_user
from eduid.webapp.common.api.messages import CommonMsg, redirect_with_msg
from eduid.webapp.common.api.utils import sanitise_redirect_url, save_and_sync_user
from eduid.webapp.common.authn.acs_enums import EidasAcsAction
from eduid.webapp.common.authn.acs_registry import acs_action
from eduid.webapp.common.authn.eduid_saml2 import get_authn_ctx
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.authn.utils import get_saml_attribute
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import MfaActionError, SP_AuthnRequest
from eduid.webapp.eidas.app import current_eidas_app as current_app
from eduid.webapp.eidas.helpers import EidasMsg, is_required_loa, is_valid_reauthn, verify_nin_from_external_mfa

__author__ = 'lundberg'


@acs_action(EidasAcsAction.token_verify)
@require_user
def token_verify_action(
    session_info: SessionInfo, user: User, authndata: Optional[SP_AuthnRequest]
) -> WerkzeugResponse:
    """
    Use a Sweden Connect federation IdP assertion to verify a users MFA token and, if necessary,
    the users identity.

    :param session_info: the SAML session info
    :param user: Central db user
    :param authndata: authentication data

    :return: redirect response
    """
    redirect_url = current_app.conf.token_verify_redirect_url

    if not is_required_loa(session_info, 'loa3'):
        return redirect_with_msg(redirect_url, EidasMsg.authn_context_mismatch)

    if not is_valid_reauthn(session_info):
        return redirect_with_msg(redirect_url, EidasMsg.reauthn_expired)

    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    token_to_verify = proofing_user.credentials.find(session.eidas.verify_token_action_credential_id)
    if not isinstance(token_to_verify, FidoCredential):
        current_app.logger.error(f'Credential {token_to_verify} is not a FidoCredential')
        return redirect_with_msg(redirect_url, EidasMsg.token_not_in_creds)

    # Check (again) if token was used to authenticate this session. The first time we checked,
    # we verified that the token was used very recently, but we have to allow for more time
    # here since the user might have spent a couple of minutes authenticating with the external IdP.
    if not credential_used_to_authenticate(token_to_verify, max_age=300):
        return redirect_with_msg(redirect_url, EidasMsg.token_not_in_creds)

    # Verify asserted NIN for user if there are no verified NIN
    if len(proofing_user.nins.verified) == 0:
        error_message = verify_nin_from_external_mfa(proofing_user=proofing_user, session_info=session_info)
        if error_message is not None:
            return redirect_with_msg(redirect_url, error_message)
        # verify_nin_from_external_mfa modifies the user in the database, so we have to load it again.
        # TODO: refactor verify_nin_from_external_mfa into one action, and one worker function. Call the worker function
        #       with both user and proofing_user as arguments, and have them modified in-place to avoid a bunch
        #       of database operations.
        updated_user = current_app.central_userdb.get_user_by_eppn(user.eppn)
        if not updated_user:
            # mostly keep mypy calm
            raise RuntimeError(f'User {user} disappeared')
        user = updated_user
        proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
        token_to_verify = proofing_user.credentials.find(session.eidas.verify_token_action_credential_id)
        # Keep type checking calm
        if not token_to_verify:
            raise RuntimeError(f'Credential {session.eidas.verify_token_action_credential_id} disappeared')

    # Check that a verified NIN is equal to the asserted attribute personalIdentityNumber
    _nin_list = get_saml_attribute(session_info, 'personalIdentityNumber')

    if _nin_list is None:
        raise ValueError("Missing NIN in SAML session info")

    asserted_nin = _nin_list[0]
    user_nin = proofing_user.nins.find(asserted_nin)
    if not user_nin or not user_nin.is_verified:
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
def nin_verify_action(session_info: SessionInfo, authndata: Optional[SP_AuthnRequest], user: User) -> WerkzeugResponse:
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
        raise ValueError("Missing NIN in SAML session info")

    asserted_nin = _nin_list[0]

    if not asserted_nin:
        raise ValueError(f'Missing NIN in SAML session info: {_nin_list}')

    if len(proofing_user.nins.verified) != 0:
        current_app.logger.error('User already has a verified NIN')
        if proofing_user.nins.primary:
            current_app.logger.debug(f'Primary NIN: {proofing_user.nins.primary.number}. Asserted NIN: {asserted_nin}')
        else:
            current_app.logger.debug(f'Primary NIN: {proofing_user.nins.primary}. Asserted NIN: {asserted_nin}')
        return redirect_with_msg(redirect_url, EidasMsg.nin_already_verified)

    message = verify_nin_from_external_mfa(proofing_user=proofing_user, session_info=session_info)
    if message is not None:
        return redirect_with_msg(redirect_url, message)

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

    if len(proofing_user.nins.verified) != 0:
        current_app.logger.error('User already has a verified NIN')
        if proofing_user.nins.primary:
            current_app.logger.debug(f'Primary NIN: {proofing_user.nins.primary.number}. Asserted NIN: {asserted_nin}')
        else:
            current_app.logger.debug(f'Primary NIN: {proofing_user.nins.primary}. Asserted NIN: {asserted_nin}')
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
def mfa_authentication_action(session_info: SessionInfo, authndata: SP_AuthnRequest) -> WerkzeugResponse:
    #
    # TODO: Stop redirecting with message after we stop using actions
    #
    redirect_url = sanitise_redirect_url(authndata.redirect_url)

    if not is_required_loa(session_info, 'loa3'):
        session.mfa_action.error = MfaActionError.authn_context_mismatch
        return redirect_with_msg(redirect_url, EidasMsg.authn_context_mismatch)

    if not is_valid_reauthn(session_info):
        session.mfa_action.error = MfaActionError.authn_too_old
        return redirect_with_msg(redirect_url, EidasMsg.reauthn_expired)

    # Check that third party service returned a NIN
    _personal_idns = get_saml_attribute(session_info, 'personalIdentityNumber')
    if _personal_idns is None:
        current_app.logger.error(
            'Got no personalIdentityNumber attributes. pysaml2 without the right attribute_converter?'
        )
        # TODO: change to reasonable redirect_with_msg when the ENUM work for that is merged
        raise RuntimeError('Got no attribute personalIdentityNumber')

    # Get user from central database
    user = current_app.central_userdb.get_user_by_eppn(session.common.eppn)
    if user is None:
        # Please mypy
        raise RuntimeError(f'No user with eppn {session.common.eppn} found')

    # Check that a verified NIN is equal to the asserted attribute personalIdentityNumber
    asserted_nin = _personal_idns[0]
    user_nin = user.nins.find(asserted_nin)
    locked_nin = user.locked_identity.find('nin')

    mfa_success = False
    if user_nin is None and locked_nin is None:
        # no nin to match anything to
        mfa_success = False
    elif user_nin is not None and user_nin.is_verified is True:
        # nin matched asserted nin and is verified
        mfa_success = True
    elif isinstance(locked_nin, LockedIdentityNin) and locked_nin.number == asserted_nin:
        # previously verified nin that the user just showed possession of
        mfa_success = True
        # and we can verify it again
        proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
        message = verify_nin_from_external_mfa(proofing_user=proofing_user, session_info=session_info)
        if message is not None:
            return redirect_with_msg(redirect_url, message)

    if not mfa_success:
        # No nin to match external mfa authentication with, bail
        current_app.logger.error('Asserted NIN not matching user verified nins')
        current_app.logger.debug('Asserted NIN: {}'.format(asserted_nin))
        current_app.stats.count(name='mfa_auth_nin_not_matching')
        session.mfa_action.error = MfaActionError.nin_not_matching
        return redirect_with_msg(redirect_url, EidasMsg.nin_not_matching)

    session.mfa_action.success = mfa_success
    session.mfa_action.issuer = session_info['issuer']
    session.mfa_action.authn_instant = session_info['authn_info'][0][2]
    session.mfa_action.authn_context = get_authn_ctx(session_info)
    current_app.stats.count(name='mfa_auth_success')
    current_app.stats.count(name=f'mfa_auth_{session_info["issuer"]}_success')
    current_app.logger.info(f'Redirecting to: {redirect_url}')
    return redirect_with_msg(redirect_url, EidasMsg.action_completed, error=False)
