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
    run_mfa_authenticate,
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
        app=current_app,
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
        app=current_app,
    )


@acs_action(BankIDAcsAction.mfa_authenticate)
def mfa_authenticate_action(args: ACSArgs) -> ACSResult:
    """Authenticate a user using a Sweden Connect federation IdP assertion."""
    result = run_mfa_authenticate(
        args,
        common_saml_checks=common_saml_checks,
        get_proofing_functions=get_proofing_functions,
        get_user=lambda: current_app.central_userdb.get_user_by_eppn(session.mfa_action.eppn),
        method_not_available_msg=BankIDMsg.method_not_available,
        identity_not_matching_msg=BankIDMsg.identity_not_matching,
        mfa_authn_success_msg=BankIDMsg.mfa_authn_success,
        app=current_app,
    )
    if result.success:
        assert args.proofing_method is not None
        parsed = args.proofing_method.parse_session_info(args.session_info, backdoor=args.backdoor)
        assert isinstance(parsed.info, BaseSessionInfo)
        current_app.stats.count(name=f"mfa_auth_{parsed.info.issuer}_success")
    return result


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
        app=current_app,
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
