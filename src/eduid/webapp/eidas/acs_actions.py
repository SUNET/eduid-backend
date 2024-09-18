from eduid.userdb import User
from eduid.userdb.credentials.fido import FidoCredential
from eduid.webapp.common.api.decorators import require_user
from eduid.webapp.common.api.messages import AuthnStatusMsg
from eduid.webapp.common.authn.acs_enums import EidasAcsAction
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult, acs_action
from eduid.webapp.common.proofing.messages import ProofingMsg
from eduid.webapp.common.proofing.methods import ProofingMethodSAML
from eduid.webapp.common.proofing.saml_helpers import authn_ctx_to_loa, is_required_loa, is_valid_authn_instant
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import SP_AuthnRequest
from eduid.webapp.eidas.app import current_eidas_app as current_app
from eduid.webapp.eidas.helpers import EidasMsg, check_reauthn
from eduid.webapp.eidas.proofing import get_proofing_functions
from eduid.webapp.eidas.saml_session_info import BaseSessionInfo

__author__ = "lundberg"


def common_saml_checks(args: ACSArgs) -> ACSResult | None:
    """
    Check that the user is authenticated and that the session info is valid.
    """
    assert isinstance(args.proofing_method, ProofingMethodSAML)  # please mypy
    if not is_required_loa(
        args.session_info, args.proofing_method.required_loa, current_app.conf.authentication_context_map
    ):
        current_app.logger.error("SAML response did not meet required LOA")
        args.authn_req.error = True
        args.authn_req.status = EidasMsg.authn_context_mismatch.value
        return ACSResult(message=EidasMsg.authn_context_mismatch)

    if not is_valid_authn_instant(args.session_info):
        current_app.logger.error("SAML response was not a valid reauthn")
        args.authn_req.error = True
        args.authn_req.status = EidasMsg.authn_instant_too_old.value
        return ACSResult(message=EidasMsg.authn_instant_too_old)

    return None


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
        return ACSResult(message=EidasMsg.method_not_available)

    # validate the assertion data
    if ret := common_saml_checks(args=args):
        return ret

    parsed = args.proofing_method.parse_session_info(args.session_info, backdoor=args.backdoor)
    if parsed.error:
        return ACSResult(message=parsed.error)

    # please type checking
    assert isinstance(parsed.info, BaseSessionInfo)

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

    return ACSResult(success=True, message=EidasMsg.identity_verify_success)


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
        return ACSResult(message=EidasMsg.method_not_available)

    # validate the assertion data
    if ret := common_saml_checks(args=args):
        return ret

    assert isinstance(args.authn_req, SP_AuthnRequest)

    credential = user.credentials.find(args.authn_req.proofing_credential_id)
    if not isinstance(credential, FidoCredential):
        current_app.logger.error(f"Credential {credential} is not a FidoCredential")
        return ACSResult(message=EidasMsg.credential_not_found)

    # Check (again) if token was used to authenticate this session and that the auth is not stale.
    _need_reauthn = check_reauthn(frontend_action=args.authn_req.frontend_action, user=user, credential_used=credential)
    if _need_reauthn:
        current_app.logger.error(f"User needs to authenticate: {_need_reauthn}")
        return ACSResult(message=AuthnStatusMsg.must_authenticate)

    parsed = args.proofing_method.parse_session_info(args.session_info, args.backdoor)
    if parsed.error:
        return ACSResult(message=parsed.error)

    # please type checking
    assert isinstance(parsed.info, BaseSessionInfo)

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
                return ACSResult(message=EidasMsg.credential_not_found)

    # Check that the users' verified identity matches the one that was asserted now
    match_res = proofing.match_identity(user=user, proofing_method=args.proofing_method)
    if match_res.error is not None:
        return ACSResult(message=match_res.error)

    if not match_res.matched:
        # Matching external mfa authentication with user nin failed, bail
        current_app.stats.count(name=f"verify_credential_{args.proofing_method.method}_identity_not_matching")
        return ACSResult(message=EidasMsg.identity_not_matching)

    loa = authn_ctx_to_loa(args.session_info, current_app.conf.authentication_context_map)

    verify_result = proofing.verify_credential(user=user, credential=credential, loa=loa)
    if verify_result.error is not None:
        return ACSResult(message=verify_result.error)

    current_app.stats.count(name="fido_token_verified")
    current_app.stats.count(name=f"verify_credential_{args.proofing_method.method}_success")

    return ACSResult(success=True, message=EidasMsg.credential_verify_success)


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
        return ACSResult(message=EidasMsg.method_not_available)

    # validate the assertion data
    if ret := common_saml_checks(args=args):
        return ret

    # Get user from central database
    user = current_app.central_userdb.get_user_by_eppn(session.common.eppn)

    parsed = args.proofing_method.parse_session_info(args.session_info, backdoor=args.backdoor)
    if parsed.error:
        return ACSResult(message=parsed.error)

    # please type checking
    assert isinstance(parsed.info, BaseSessionInfo)

    proofing = get_proofing_functions(
        session_info=parsed.info, app_name=current_app.conf.app_name, config=current_app.conf, backdoor=args.backdoor
    )

    # Check that a verified NIN is equal to the asserted attribute personalIdentityNumber
    match_res = proofing.match_identity(user=user, proofing_method=args.proofing_method)
    current_app.logger.debug(f"MFA authentication identity matching result: {match_res}")
    if match_res.error is not None:
        return ACSResult(message=match_res.error)

    if not match_res.matched:
        # Matching external mfa authentication with user nin failed, bail
        current_app.stats.count(name=f"mfa_auth_{args.proofing_method.method}_identity_not_matching")
        return ACSResult(message=EidasMsg.identity_not_matching)

    current_app.stats.count(name="mfa_auth_success")
    current_app.stats.count(name=f"mfa_auth_{args.proofing_method.method}_success")
    current_app.stats.count(name=f"mfa_auth_{parsed.info.issuer}_success")
    return ACSResult(success=True, message=EidasMsg.mfa_authn_success)
