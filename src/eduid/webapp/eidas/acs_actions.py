# -*- coding: utf-8 -*-

from flask import request
from pydantic import ValidationError
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.rpc.exceptions import AmTaskFailed, MsgTaskFailed, NoNavetData
from eduid.userdb import User
from eduid.userdb.credentials.fido import FidoCredential
from eduid.userdb.logs import MFATokenProofing
from eduid.userdb.proofing.user import ProofingUser
from eduid.webapp.authn.helpers import credential_used_to_authenticate
from eduid.webapp.common.api.decorators import require_user
from eduid.webapp.common.api.helpers import check_magic_cookie, get_proofing_log_navet_data
from eduid.webapp.common.api.messages import CommonMsg, redirect_with_msg
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.common.authn.acs_enums import EidasAcsAction
from eduid.webapp.common.authn.acs_registry import acs_action
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import MfaActionError, SP_AuthnRequest
from eduid.webapp.eidas.app import current_eidas_app as current_app
from eduid.webapp.eidas.helpers import (
    EidasMsg,
    create_eidas_mfa_proofing_element,
    match_identity_for_mfa,
    token_verify_BACKDOOR,
    verify_eidas_from_external_mfa,
    verify_nin_from_external_mfa,
)
from eduid.webapp.eidas.saml_session_info import NinSessionInfo

__author__ = 'lundberg'

from eduid.webapp.eidas.saml_session_info import ForeignEidSessionInfo


@acs_action(EidasAcsAction.token_verify)
@require_user
def token_verify_action(session_info: SessionInfo, user: User, authndata: SP_AuthnRequest) -> WerkzeugResponse:
    """
    Use a Sweden Connect federation IdP assertion to verify a users MFA token and, if necessary,
    the users identity.

    :param session_info: the SAML session info
    :param user: Central db user
    :param authndata: authentication data

    :return: redirect response
    """
    redirect_url = authndata.redirect_url

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

    try:
        parsed_session_info = NinSessionInfo(**session_info)
        current_app.logger.debug(f'session info: {parsed_session_info}')
    except ValidationError:
        current_app.logger.exception('missing attribute in SAML response')
        # TODO: redirect user back with an error message i session using ref
        return redirect_with_msg(redirect_url, EidasMsg.attribute_missing)

    # Verify asserted NIN for user if there are no verified NIN
    if proofing_user.identities.nin is None or proofing_user.identities.nin.is_verified is False:
        verify_result = verify_nin_from_external_mfa(proofing_user=proofing_user, session_info=parsed_session_info)
        if verify_result.error_message is not None:
            return redirect_with_msg(redirect_url, verify_result.error_message)
        if not verify_result.user:
            # mostly keep mypy calm
            raise RuntimeError(f'User {user} disappeared')
        proofing_user = verify_result.user
        token_to_verify = proofing_user.credentials.find(session.eidas.verify_token_action_credential_id)
        # Keep type checking calm
        if not token_to_verify:
            raise RuntimeError(f'Credential {session.eidas.verify_token_action_credential_id} disappeared')

    asserted_nin = parsed_session_info.attributes.nin
    if check_magic_cookie(current_app.conf):
        # change asserted nin to nin from the integration test cookie
        magic_cookie_nin = request.cookies.get('nin')
        if magic_cookie_nin is None:
            current_app.logger.error("Bad nin cookie")
            return redirect_with_msg(redirect_url, EidasMsg.nin_not_matching)
        asserted_nin = magic_cookie_nin

    if (
        proofing_user.identities.nin is None
        or proofing_user.identities.nin.number != asserted_nin
        or proofing_user.identities.nin.is_verified is False
    ):
        current_app.logger.error('Asserted NIN not matching user verified nins')
        current_app.logger.debug('Asserted NIN: {}'.format(asserted_nin))
        return redirect_with_msg(redirect_url, EidasMsg.nin_not_matching)

    if check_magic_cookie(current_app.conf):
        return token_verify_BACKDOOR(
            proofing_user=proofing_user,
            asserted_nin=asserted_nin,
            token_to_verify=token_to_verify,
            redirect_url=redirect_url,
        )

    # Create a proofing log
    current_app.logger.debug('Issuer: {}'.format(parsed_session_info.issuer))
    current_app.logger.debug('Authn context: {}'.format(parsed_session_info.authn_context))
    try:
        navet_proofing_data = get_proofing_log_navet_data(nin=proofing_user.identities.nin.number)
    except NoNavetData:
        current_app.logger.exception('No data returned from Navet')
        return redirect_with_msg(redirect_url, CommonMsg.no_navet_data)
    except MsgTaskFailed:
        current_app.logger.exception('Navet lookup failed')
        current_app.stats.count('navet_error')
        return redirect_with_msg(redirect_url, CommonMsg.navet_error)

    proofing_log_entry = MFATokenProofing(
        eppn=proofing_user.eppn,
        created_by=current_app.conf.app_name,
        nin=proofing_user.identities.nin.number,
        issuer=parsed_session_info.issuer,
        authn_context_class=parsed_session_info.authn_context,
        key_id=token_to_verify.key,
        user_postal_address=navet_proofing_data.user_postal_address,
        deregistration_information=navet_proofing_data.deregistration_information,
        proofing_version=current_app.conf.security_key_proofing_version,
    )

    # Set token as verified
    token_to_verify.is_verified = True
    token_to_verify.proofing_method = current_app.conf.security_key_proofing_method
    token_to_verify.proofing_version = current_app.conf.security_key_proofing_version

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


@acs_action(EidasAcsAction.token_verify_foreign_eid)
@require_user
def token_verify_foreign_eid_action(
    session_info: SessionInfo, user: User, authndata: SP_AuthnRequest
) -> WerkzeugResponse:
    """
    Use a Sweden Connect federation IdP assertion to verify a users MFA token and, if necessary,
    the users identity.

    :param session_info: the SAML session info
    :param user: Central db user
    :param authndata: authentication data

    :return: redirect response
    """
    redirect_url = authndata.redirect_url

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

    try:
        parsed_session_info = ForeignEidSessionInfo(**session_info)
        current_app.logger.debug(f'session info: {parsed_session_info}')
    except ValidationError:
        current_app.logger.exception('missing attribute in SAML response')
        # TODO: redirect user back with an error message i session using ref
        return redirect_with_msg(redirect_url, EidasMsg.attribute_missing)

    # Verify asserted identity for user if there are no verified eidas
    if proofing_user.identities.eidas is None or proofing_user.identities.eidas.is_verified is False:
        verify_result = verify_eidas_from_external_mfa(proofing_user=proofing_user, session_info=parsed_session_info)
        if verify_result.error_message is not None:
            return redirect_with_msg(redirect_url, verify_result.error_message)
        # verify_nin_from_external_mfa modifies the user in the database, so we have to load it again.
        if not verify_result.user:
            # mostly keep mypy calm
            raise RuntimeError(f'User {user} disappeared')
        proofing_user = verify_result.user
        token_to_verify = proofing_user.credentials.find(session.eidas.verify_token_action_credential_id)
        # Keep type checking calm
        if not token_to_verify:
            raise RuntimeError(f'Credential {session.eidas.verify_token_action_credential_id} disappeared')

    if (
        proofing_user.identities.eidas is None
        or proofing_user.identities.eidas.prid != parsed_session_info.attributes.prid
        or proofing_user.identities.eidas.is_verified is False
    ):
        current_app.logger.error('Asserted identity not matching user verified eidas')
        current_app.logger.debug('Asserted NIN: {}'.format(parsed_session_info.attributes.prid))
        return redirect_with_msg(redirect_url, EidasMsg.foreign_eid_not_matching)

    current_app.logger.debug('Issuer: {}'.format(parsed_session_info.issuer))
    current_app.logger.debug('Authn context: {}'.format(parsed_session_info.authn_context))

    proofing_log_entry = create_eidas_mfa_proofing_element(
        proofing_user=proofing_user, session_info=parsed_session_info, token_to_verify=token_to_verify
    )

    # Set token as verified
    token_to_verify.is_verified = True
    token_to_verify.proofing_method = current_app.conf.security_key_proofing_method
    token_to_verify.proofing_version = current_app.conf.security_key_foreign_eid_proofing_version

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
def nin_verify_action(session_info: SessionInfo, authndata: SP_AuthnRequest, user: User) -> WerkzeugResponse:
    """
    Use a Sweden Connect federation IdP assertion to verify a users identity.

    :param session_info: the SAML session info
    :param authndata: authentication request data
    :param user: Central db user

    :return: redirect response
    """
    redirect_url = authndata.redirect_url

    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    try:
        parsed_session_info = NinSessionInfo(**session_info)
        current_app.logger.debug(f'session info: {parsed_session_info}')
    except ValidationError:
        current_app.logger.exception('missing attribute in SAML response')
        # TODO: redirect user back with an error message i session using ref
        return redirect_with_msg(redirect_url, EidasMsg.attribute_missing)

    asserted_nin = parsed_session_info.attributes.nin

    if check_magic_cookie(current_app.conf):
        # change asserted nin to nin from the integration test cookie
        magic_cookie_nin = request.cookies.get('nin')
        if magic_cookie_nin is None:
            current_app.logger.error("Bad nin cookie")
            return redirect_with_msg(redirect_url, CommonMsg.nin_invalid)
        asserted_nin = magic_cookie_nin

    if proofing_user.identities.nin and proofing_user.identities.nin.is_verified:
        current_app.logger.error('User already has a verified NIN')
        current_app.logger.debug(f'NIN: {proofing_user.identities.nin}. Asserted NIN: {asserted_nin}')
        return redirect_with_msg(redirect_url, EidasMsg.nin_already_verified)

    verify_result = verify_nin_from_external_mfa(proofing_user=proofing_user, session_info=parsed_session_info)
    if verify_result.error_message is not None:
        return redirect_with_msg(redirect_url, verify_result.error_message)

    return redirect_with_msg(redirect_url, EidasMsg.nin_verify_success, error=False)


@acs_action(EidasAcsAction.foreign_identity_verify)
@require_user
def verify_foreign_identity(session_info: SessionInfo, authndata: SP_AuthnRequest, user: User) -> WerkzeugResponse:
    redirect_url = authndata.redirect_url

    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)

    current_app.logger.debug(f'session_info: {session_info}')
    current_app.logger.debug(f'authndata: {authndata}')

    try:
        parsed_session_info = ForeignEidSessionInfo(**session_info)
        current_app.logger.debug(f'session info: {parsed_session_info}')
    except ValidationError:
        current_app.logger.exception('missing attribute in SAML response')
        # TODO: redirect user back with an error message i session using ref
        return redirect_with_msg(redirect_url, EidasMsg.attribute_missing)

    if proofing_user.identities.eidas and proofing_user.identities.eidas.is_verified:
        current_app.logger.error('User already has a verified EIDAS identity')
        current_app.logger.debug(
            f'eidas: {proofing_user.identities.eidas}. Asserted identity: {parsed_session_info.attributes}'
        )
        return redirect_with_msg(redirect_url, EidasMsg.foreign_eid_already_verified)

    verify_result = verify_eidas_from_external_mfa(proofing_user=proofing_user, session_info=parsed_session_info)
    if verify_result.error_message is not None:
        return redirect_with_msg(redirect_url, verify_result.error_message)

    return redirect_with_msg(redirect_url, EidasMsg.foreign_eid_verify_success, error=False)


@acs_action(EidasAcsAction.mfa_authn)
def nin_mfa_authentication_action(session_info: SessionInfo, authndata: SP_AuthnRequest) -> WerkzeugResponse:
    #
    # TODO: Stop redirecting with message after we stop using actions
    #
    redirect_url = authndata.redirect_url

    try:
        parsed_session_info = NinSessionInfo(**session_info)
        current_app.logger.debug(f'session info: {parsed_session_info}')
    except ValidationError:
        current_app.logger.exception('missing attribute in SAML response')
        # TODO: redirect user back with an error message i session using ref
        return redirect_with_msg(redirect_url, EidasMsg.attribute_missing)

    # Get user from central database
    user = current_app.central_userdb.get_user_by_eppn(session.common.eppn)
    if user is None:
        # Please mypy
        raise RuntimeError(f'No user with eppn {session.common.eppn} found')

    if check_magic_cookie(current_app.conf):
        # change asserted nin to nin from the integration test cookie
        magic_cookie_nin = request.cookies.get('nin')
        if magic_cookie_nin is None:
            current_app.logger.error("Bad nin cookie")
            return redirect_with_msg(redirect_url, CommonMsg.nin_invalid)
        parsed_session_info.attributes.nin = magic_cookie_nin

    # Check that a verified NIN is equal to the asserted attribute personalIdentityNumber
    message = match_identity_for_mfa(user=user, session_info=parsed_session_info)
    if message is not None:
        return redirect_with_msg(redirect_url, message)

    if not session.mfa_action.success:
        # Matching external mfa authentication with user nin failed, bail
        current_app.logger.error('Asserted NIN not matching user verified nins')
        current_app.logger.debug('Asserted NIN: {}'.format(parsed_session_info.attributes.nin))
        current_app.stats.count(name='mfa_auth_nin_not_matching')
        session.mfa_action.error = MfaActionError.nin_not_matching
        return redirect_with_msg(redirect_url, EidasMsg.nin_not_matching)

    current_app.stats.count(name='mfa_auth_success')
    current_app.stats.count(name=f'mfa_auth_{session_info["issuer"]}_success')
    current_app.logger.info(f'Redirecting to: {redirect_url}')
    return redirect_with_msg(redirect_url, EidasMsg.action_completed, error=False)


@acs_action(EidasAcsAction.mfa_authn_foreign_eid)
def foreign_eid_mfa_authentication_action(session_info: SessionInfo, authndata: SP_AuthnRequest) -> WerkzeugResponse:
    #
    # TODO: Stop redirecting with message after we stop using actions
    #
    redirect_url = authndata.redirect_url

    try:
        parsed_session_info = ForeignEidSessionInfo(**session_info)
        current_app.logger.debug(f'session info: {parsed_session_info}')
    except ValidationError:
        current_app.logger.exception('missing attribute in SAML response')
        # TODO: redirect user back with an error message i session using ref
        return redirect_with_msg(redirect_url, EidasMsg.attribute_missing)

    # Get user from central database
    user = current_app.central_userdb.get_user_by_eppn(session.common.eppn)
    if user is None:
        # Please mypy
        raise RuntimeError(f'No user with eppn {session.common.eppn} found')

    # Check that a verified foreign eid is equal to the asserted attribute prid
    message = match_identity_for_mfa(user=user, session_info=parsed_session_info)
    if message is not None:
        return redirect_with_msg(redirect_url, message)

    if not session.mfa_action.success:
        # Matching external mfa authentication with user nin failed, bail
        current_app.logger.error('Asserted identity not matching user verified identity')
        current_app.logger.debug(f'Asserted identity: {parsed_session_info.attributes.prid}')
        current_app.stats.count(name='mfa_auth_foreign_eid_not_matching')
        session.mfa_action.error = MfaActionError.foreign_eid_not_matching
        return redirect_with_msg(redirect_url, EidasMsg.foreign_eid_not_matching)

    current_app.stats.count(name='mfa_auth_success')
    current_app.stats.count(name=f'mfa_auth_{parsed_session_info.issuer}_success')
    current_app.logger.info(f'Redirecting to: {redirect_url}')
    return redirect_with_msg(redirect_url, EidasMsg.action_completed, error=False)
