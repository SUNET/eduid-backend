# -*- coding: utf-8 -*-

from eduid.userdb import User
from eduid.userdb.credentials.fido import FidoCredential
from eduid.webapp.authn.helpers import credential_used_to_authenticate
from eduid.webapp.common.api.decorators import require_user
from eduid.webapp.common.authn.acs_enums import EidasAcsAction
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult, acs_action
from eduid.webapp.common.proofing.messages import ProofingMsg
from eduid.webapp.common.session import session
from eduid.webapp.eidas.app import current_eidas_app as current_app
from eduid.webapp.eidas.helpers import (
    EidasMsg,
    authn_ctx_to_loa,
)
from eduid.webapp.eidas.proofing import (
    get_proofing_functions,
)

__author__ = 'lundberg'


@acs_action(EidasAcsAction.verify_identity)
@require_user
def verify_identity_action(user: User, args: ACSArgs) -> ACSResult:
    """
    Use a Sweden Connect federation IdP assertion to verify a users' identity.

    :param args: ACS action arguments
    :param user: Central db user

    :return: ACS action result
    """
    # please type checking
    if not args.proofing_method:
        return ACSResult(error=EidasMsg.method_not_available)

    parsed = args.proofing_method.parse_session_info(args.session_info, backdoor=args.backdoor)
    if parsed.error:
        return ACSResult(error=parsed.error)

    # please type checking
    assert parsed.info

    proofing = get_proofing_functions(
        session_info=parsed.info, app_name=current_app.conf.app_name, config=current_app.conf, backdoor=args.backdoor
    )

    current = proofing.get_identity(user)
    if current and current.is_verified:
        current_app.logger.error(f'User already has a verified identity for {args.proofing_method.method}')
        current_app.logger.debug(f'Current: {current}. Assertion: {args.session_info}')
        return ACSResult(error=ProofingMsg.identity_already_verified)

    verify_result = proofing.verify_identity(user=user)
    if verify_result.error is not None:
        return ACSResult(error=verify_result.error)

    return ACSResult(success=True)


@acs_action(EidasAcsAction.verify_credential)
@require_user
def verify_credential_action(user: User, args: ACSArgs) -> ACSResult:
    """
    Use a Sweden Connect federation IdP assertion to person-proof a users' FIDO credential.

    :param args: ACS action arguments
    :param user: Central db user

    :return: ACS action result
    """
    # please type checking
    if not args.proofing_method:
        return ACSResult(error=EidasMsg.method_not_available)

    credential = user.credentials.find(args.authn_req.proofing_credential_id)
    if not isinstance(credential, FidoCredential):
        current_app.logger.error(f'Credential {credential} is not a FidoCredential')
        return ACSResult(error=EidasMsg.token_not_in_creds)

    # Check (again) if token was used to authenticate this session. The first time we checked,
    # we verified that the token was used very recently, but we have to allow for more time
    # here since the user might have spent a couple of minutes authenticating with the external IdP.
    if not credential_used_to_authenticate(credential, max_age=300):
        return ACSResult(error=EidasMsg.reauthn_expired)

    parsed = args.proofing_method.parse_session_info(args.session_info, args.backdoor)
    if parsed.error:
        return ACSResult(error=parsed.error)

    # please type checking
    assert parsed.info

    proofing = get_proofing_functions(
        session_info=parsed.info, app_name=current_app.conf.app_name, config=current_app.conf, backdoor=args.backdoor
    )

    _identity = proofing.get_identity(user=user)
    if not _identity or not _identity.is_verified:
        # proof users' identity too in this process if the user didn't have a verified identity of this type already
        verify_result = proofing.verify_identity(user=user)
        if verify_result.error is not None:
            return ACSResult(error=verify_result.error)
        if verify_result.user:
            # Get an updated user object
            user = verify_result.user
            # It is necessary to look up the credential again in order for changes to the instance to
            # actually be saved to the database. Can't be references to old user objects credential.
            credential = user.credentials.find(credential.key)
            if not isinstance(credential, FidoCredential):
                current_app.logger.error(f'Credential {credential} is not a FidoCredential')
                return ACSResult(error=EidasMsg.token_not_in_creds)

    # Check that the users' verified identity matches the one that was asserted now
    match_res = proofing.match_identity(user=user, proofing_method=args.proofing_method)
    if match_res.error is not None:
        return ACSResult(error=match_res.error)

    if not match_res.matched:
        # Matching external mfa authentication with user nin failed, bail
        current_app.stats.count(name=f'verify_credential_{args.proofing_method.method}_identity_not_matching')
        return ACSResult(error=EidasMsg.identity_not_matching)

    loa = authn_ctx_to_loa(args.session_info)

    verify_result = proofing.verify_credential(user=user, credential=credential, loa=loa)
    if verify_result.error is not None:
        return ACSResult(error=verify_result.error)

    current_app.stats.count(name='fido_token_verified')
    current_app.stats.count(name=f'verify_credential_{args.proofing_method.method}_success')

    return ACSResult(success=True)


@acs_action(EidasAcsAction.mfa_authenticate)
def mfa_authenticate_action(args: ACSArgs) -> ACSResult:
    """
    Authenticate a user using Use a Sweden Connect federation IdP assertion.

    NOTE: While this code looks up the user from session.common.eppn, it doesn't require the user
          to be already logged in, so it can't use the @require_user decorator.

    :param args: ACS action arguments

    :return: ACS action result
    """
    # please type checking
    if not args.proofing_method:
        return ACSResult(error=EidasMsg.method_not_available)

    # Get user from central database
    user = current_app.central_userdb.get_user_by_eppn(session.common.eppn)
    if user is None:
        # Please mypy
        raise RuntimeError(f'No user with eppn {session.common.eppn} found')

    parsed = args.proofing_method.parse_session_info(args.session_info, backdoor=args.backdoor)
    if parsed.error:
        return ACSResult(error=parsed.error)

    # please type checking
    assert parsed.info

    proofing = get_proofing_functions(
        session_info=parsed.info, app_name=current_app.conf.app_name, config=current_app.conf, backdoor=args.backdoor
    )

    # Check that a verified NIN is equal to the asserted attribute personalIdentityNumber
    match_res = proofing.match_identity(user=user, proofing_method=args.proofing_method)
    current_app.logger.debug(f'MFA authentication identity matching result: {match_res}')
    if match_res.error is not None:
        return ACSResult(error=match_res.error)

    if not match_res.matched:
        # Matching external mfa authentication with user nin failed, bail
        current_app.stats.count(name=f'mfa_auth_{args.proofing_method.method}_identity_not_matching')
        return ACSResult(error=EidasMsg.identity_not_matching)

    current_app.stats.count(name=f'mfa_auth_success')
    current_app.stats.count(name=f'mfa_auth_{args.proofing_method.method}_success')
    current_app.stats.count(name=f'mfa_auth_{parsed.info.issuer}_success')
    return ACSResult(success=True)
