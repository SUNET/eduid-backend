from eduid.userdb import User
from eduid.userdb.credentials import FidoCredential
from eduid.webapp.common.api.decorators import require_user
from eduid.webapp.common.api.messages import AuthnStatusMsg
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult, acs_action
from eduid.webapp.common.authn.utils import check_reauthn
from eduid.webapp.common.proofing.messages import ProofingMsg
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import RP_AuthnRequest
from eduid.webapp.freja_eid.app import current_freja_eid_app as current_app
from eduid.webapp.freja_eid.callback_enums import FrejaEIDAction
from eduid.webapp.freja_eid.helpers import FrejaEIDDocumentUserInfo, FrejaEIDMsg
from eduid.webapp.freja_eid.proofing import get_proofing_functions

__author__ = "lundberg"


@acs_action(FrejaEIDAction.verify_identity)
@require_user
def verify_identity_action(user: User, args: ACSArgs) -> ACSResult:
    """
    Use a Freja OIDC userinfo to verify a users' identity.
    """
    # please type checking
    if not args.proofing_method:
        return ACSResult(message=FrejaEIDMsg.method_not_available)

    parsed = args.proofing_method.parse_session_info(args.session_info, backdoor=args.backdoor)
    if parsed.error:
        return ACSResult(message=parsed.error)

    # please type checking
    assert isinstance(parsed.info, FrejaEIDDocumentUserInfo)

    proofing = get_proofing_functions(
        session_info=parsed.info, app_name=current_app.conf.app_name, config=current_app.conf, backdoor=args.backdoor
    )

    current = proofing.get_identity(user)
    if current and current.is_verified:
        current_app.logger.error(f"User already has a verified identity for {args.proofing_method.method}")
        current_app.logger.debug(f"Current: {current}. Assertion: {args.session_info}")
        return ACSResult(message=ProofingMsg.identity_already_verified)

    verify_result = proofing.verify_identity(user=user)
    if verify_result.error is not None:
        return ACSResult(message=verify_result.error)

    return ACSResult(success=True, message=FrejaEIDMsg.identity_verify_success)


@acs_action(FrejaEIDAction.verify_credential)
@require_user
def verify_credential_action(user: User, args: ACSArgs) -> ACSResult:
    """
    Use a Freja eID assertion to person-proof a users' FIDO credential.

    :param args: ACS action arguments
    :param user: Central db user

    :return: ACS action result
    """
    # please type checking
    if not args.proofing_method:
        return ACSResult(message=FrejaEIDMsg.method_not_available)

    assert isinstance(args.authn_req, RP_AuthnRequest)

    credential = user.credentials.find(args.authn_req.proofing_credential_id)
    if not isinstance(credential, FidoCredential):
        current_app.logger.error(f"Credential {credential} is not a FidoCredential")
        return ACSResult(message=FrejaEIDMsg.credential_not_found)

    # Check (again) if token was used to authenticate this session and that the auth is not stale.
    _need_reauthn = check_reauthn(
        frontend_action=args.authn_req.frontend_action, user=user, credential_requested=credential
    )
    if _need_reauthn:
        current_app.logger.error(f"User needs to authenticate: {_need_reauthn}")
        return ACSResult(message=AuthnStatusMsg.must_authenticate)

    parsed = args.proofing_method.parse_session_info(args.session_info, args.backdoor)
    if parsed.error:
        return ACSResult(message=parsed.error)

    # please type checking
    assert isinstance(parsed.info, FrejaEIDDocumentUserInfo)

    proofing = get_proofing_functions(
        session_info=parsed.info, app_name=current_app.conf.app_name, config=current_app.conf, backdoor=args.backdoor
    )

    _identity = proofing.get_identity(user=user)
    if not _identity or not _identity.is_verified:
        # proof users' identity too in this process if the user didn't have a verified identity of this type already
        verify_result = proofing.verify_identity(user=user)
        if verify_result.error is not None:
            return ACSResult(message=verify_result.error)
        if verify_result.user:
            # Get an updated user object
            user = verify_result.user
            # It is necessary to look up the credential again in order for changes to the instance to
            # actually be saved to the database. Can't be references to old user objects credential.
            credential = user.credentials.find(credential.key)
            if not isinstance(credential, FidoCredential):
                current_app.logger.error(f"Credential {credential} is not a FidoCredential")
                return ACSResult(message=FrejaEIDMsg.credential_not_found)

    # Check that the users' verified identity matches the one that was asserted now
    match_res = proofing.match_identity(user=user, proofing_method=args.proofing_method)
    if match_res.error is not None:
        return ACSResult(message=match_res.error)

    if not match_res.matched:
        # Matching external mfa authentication with user identity failed, bail
        current_app.stats.count(name=f"verify_credential_{args.proofing_method.method}_identity_not_matching")
        return ACSResult(message=FrejaEIDMsg.identity_not_matching)

    current_loa = proofing.get_current_loa()
    if current_loa.result is None:
        current_app.logger.error(f"No LOA configured for registration level {parsed.info.registration_level}")
        return ACSResult(message=FrejaEIDMsg.registration_level_not_satisfied)

    verify_result = proofing.verify_credential(user=user, credential=credential, loa=current_loa.result)
    if verify_result.error is not None:
        return ACSResult(message=verify_result.error)

    current_app.stats.count(name="fido_token_verified")
    current_app.stats.count(name=f"verify_credential_{args.proofing_method.method}_success")

    return ACSResult(success=True, message=FrejaEIDMsg.credential_verify_success)


@acs_action(FrejaEIDAction.mfa_authenticate)
def mfa_authenticate_action(args: ACSArgs) -> ACSResult:
    """
    Authenticate a user using Freja eID.

    :param args: ACS action arguments

    :return: ACS action result
    """
    # please type checking
    if not args.proofing_method:
        return ACSResult(message=FrejaEIDMsg.method_not_available)

    # Get user from central database
    user = current_app.central_userdb.get_user_by_eppn(session.mfa_action.eppn)

    parsed = args.proofing_method.parse_session_info(args.session_info, backdoor=args.backdoor)
    if parsed.error:
        return ACSResult(message=parsed.error)

    # please type checking
    assert isinstance(parsed.info, FrejaEIDDocumentUserInfo)

    proofing = get_proofing_functions(
        session_info=parsed.info, app_name=current_app.conf.app_name, config=current_app.conf, backdoor=args.backdoor
    )

    # Check that NIN or Freja eID user id is equal to the asserted attribute
    match_res = proofing.match_identity(user=user, proofing_method=args.proofing_method)
    current_app.logger.debug(f"MFA authentication identity matching result: {match_res}")
    if match_res.error is not None:
        return ACSResult(message=match_res.error)

    if not match_res.matched:
        # Matching external mfa authentication with user data failed, bail
        current_app.stats.count(name=f"mfa_auth_{args.proofing_method.method}_identity_not_matching")
        return ACSResult(message=FrejaEIDMsg.identity_not_matching)

    current_app.stats.count(name="mfa_auth_success")
    current_app.stats.count(name=f"mfa_auth_{args.proofing_method.method}_success")
    current_app.stats.count(name="mfa_auth_freja_eid_success")
    return ACSResult(success=True, message=FrejaEIDMsg.mfa_authn_success)
