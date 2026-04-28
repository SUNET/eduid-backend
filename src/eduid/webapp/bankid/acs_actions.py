from eduid.userdb import User
from eduid.webapp.bankid.app import current_bankid_app as current_app
from eduid.webapp.bankid.helpers import BankIDMsg
from eduid.webapp.bankid.proofing import get_proofing_functions
from eduid.webapp.bankid.saml_session_info import BankIDSessionInfo
from eduid.webapp.common.api.decorators import require_user
from eduid.webapp.common.authn.acs_enums import BankIDAcsAction
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult, acs_action
from eduid.webapp.common.proofing.mfa_signup import MfaRegisterParsed, parse_mfa_register_args
from eduid.webapp.common.proofing.shared_actions import (
    run_common_saml_checks,
    run_verify_credential,
    run_verify_identity,
)
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import ExternalMfaSignupIdentity

__author__ = "lundberg"

from eduid.common.models.saml_models import BaseSessionInfo


def common_saml_checks(args: ACSArgs) -> ACSResult | None:
    """Perform common checks for SAML ACS actions."""
    return run_common_saml_checks(
        args,
        authn_context_mismatch_msg=BankIDMsg.authn_context_mismatch,
        authn_instant_too_old_msg=BankIDMsg.authn_instant_too_old,
        loa_authn_context_map=current_app.conf.loa_authn_context_map,
    )


@acs_action(BankIDAcsAction.verify_identity)
@require_user
def verify_identity_action(user: User, args: ACSArgs) -> ACSResult:
    """Use a Sweden Connect federation IdP assertion to verify a users' identity."""
    return run_verify_identity(
        user,
        args,
        common_saml_checks=common_saml_checks,
        get_proofing_functions=get_proofing_functions,
        method_not_available_msg=BankIDMsg.method_not_available,
        identity_verify_success_msg=BankIDMsg.identity_verify_success,
        app_name=current_app.conf.app_name,
        config=current_app.conf,
    )


@acs_action(BankIDAcsAction.verify_credential)
@require_user
def verify_credential_action(user: User, args: ACSArgs) -> ACSResult:
    """Use a Sweden Connect federation IdP assertion to person-proof a users' FIDO credential."""
    return run_verify_credential(
        user,
        args,
        common_saml_checks=common_saml_checks,
        get_proofing_functions=get_proofing_functions,
        method_not_available_msg=BankIDMsg.method_not_available,
        credential_not_found_msg=BankIDMsg.credential_not_found,
        identity_not_matching_msg=BankIDMsg.identity_not_matching,
        credential_verify_success_msg=BankIDMsg.credential_verify_success,
        app_name=current_app.conf.app_name,
        config=current_app.conf,
    )


@acs_action(BankIDAcsAction.mfa_authenticate)
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
        return ACSResult(message=BankIDMsg.method_not_available)

    if ret := common_saml_checks(args=args):
        return ret

    # Get user from central database
    user = current_app.central_userdb.get_user_by_eppn(session.mfa_action.eppn)

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
        return ACSResult(message=BankIDMsg.identity_not_matching)

    current_app.stats.count(name="mfa_auth_success")
    current_app.stats.count(name=f"mfa_auth_{args.proofing_method.method}_success")
    current_app.stats.count(name=f"mfa_auth_{parsed.info.issuer}_success")
    return ACSResult(success=True, message=BankIDMsg.mfa_authn_success)


@acs_action(BankIDAcsAction.mfa_register)
def mfa_register_action(args: ACSArgs) -> ACSResult:
    """Parse the external MFA assertion for a signup-flow authn and persist
    identity + LoA on the SP_AuthnRequest.

    No user exists yet, no DB write, no proofing log.
    """
    parsed = parse_mfa_register_args(
        args,
        common_saml_checks=common_saml_checks,
        get_proofing_functions=get_proofing_functions,
        method_not_available_msg=BankIDMsg.method_not_available,
        app_name=current_app.conf.app_name,
        config=current_app.conf,
    )
    if isinstance(parsed, ACSResult):
        return parsed
    assert isinstance(parsed, MfaRegisterParsed)  # type narrowing

    match parsed.session_info:
        case BankIDSessionInfo():
            nin = parsed.session_info.attributes.nin
            args.authn_req.external_mfa_signup_identity = ExternalMfaSignupIdentity(
                given_name=parsed.session_info.attributes.given_name,
                surname=parsed.session_info.attributes.surname,
                nin=nin,
                framework=parsed.framework,
                loa=parsed.loa,
            )
        case _:
            current_app.logger.error(f"Unsupported session info type: {type(parsed.session_info)}")
            return ACSResult(message=BankIDMsg.method_not_available)

    return ACSResult(success=True, message=BankIDMsg.mfa_authn_success)
