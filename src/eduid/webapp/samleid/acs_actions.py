from datetime import UTC, datetime

from eduid.common.models.saml_models import BaseSessionInfo
from eduid.userdb import User
from eduid.webapp.common.api.decorators import require_user
from eduid.webapp.common.authn.acs_enums import SamlEidAcsAction
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
from eduid.webapp.samleid.app import current_samleid_app as current_app
from eduid.webapp.samleid.helpers import SamlEidMsg
from eduid.webapp.samleid.proofing import get_proofing_functions
from eduid.webapp.samleid.saml_session_info import BankIDSessionInfo, ForeignEidSessionInfo, NinSessionInfo

__author__ = "lundberg"


def common_saml_checks(args: ACSArgs) -> ACSResult | None:
    """Perform common checks for SAML ACS actions."""
    return run_common_saml_checks(
        args,
        authn_context_mismatch_msg=SamlEidMsg.authn_context_mismatch,
        authn_instant_too_old_msg=SamlEidMsg.authn_instant_too_old,
        method_not_available=SamlEidMsg.method_not_available,
        loa_authn_context_map=current_app.conf.loa_authn_context_map,
    )


@acs_action(SamlEidAcsAction.verify_identity)
@require_user
def samleid_verify_identity_action(user: User, args: ACSArgs) -> ACSResult:
    """
    Use a SAML IdP assertion to verify a user's identity.

    This action handles identity verification for all supported methods:
    - Freja eID (Swedish NIN via NinSessionInfo)
    - BankID (Swedish NIN via BankIDSessionInfo)
    - eIDAS (Foreign identity via ForeignEidSessionInfo)

    The appropriate proofing functions are automatically selected based on
    the session info type from the SAML assertion.

    :param user: Central db user
    :param args: ACS action arguments

    :returns: ACS action result
    """
    return run_verify_identity(
        user,
        args,
        common_saml_checks=common_saml_checks,
        get_proofing_functions=get_proofing_functions,
        method_not_available_msg=SamlEidMsg.method_not_available,
        identity_verify_success_msg=SamlEidMsg.identity_verify_success,
        app=current_app,
    )


@acs_action(SamlEidAcsAction.verify_credential)
@require_user
def samleid_verify_credential_action(user: User, args: ACSArgs) -> ACSResult:
    """
    Use a SAML IdP assertion to person-proof a user's FIDO credential.

    This action handles credential verification for all supported methods:
    - Freja eID (Swedish NIN via NinSessionInfo)
    - BankID (Swedish NIN via BankIDSessionInfo)
    - eIDAS (Foreign identity via ForeignEidSessionInfo)

    If the user doesn't have a verified identity for this method, their identity
    will be verified as part of this process.

    :param user: Central db user
    :param args: ACS action arguments

    :returns: ACS action result
    """
    return run_verify_credential(
        user,
        args,
        common_saml_checks=common_saml_checks,
        get_proofing_functions=get_proofing_functions,
        method_not_available_msg=SamlEidMsg.method_not_available,
        credential_not_found_msg=SamlEidMsg.credential_not_found,
        identity_not_matching_msg=SamlEidMsg.identity_not_matching,
        credential_verify_success_msg=SamlEidMsg.credential_verify_success,
        app=current_app,
    )


@acs_action(SamlEidAcsAction.mfa_authenticate)
def samleid_mfa_authenticate_action(args: ACSArgs) -> ACSResult:
    """
    Authenticate a user using a SAML IdP assertion for multi-factor authentication.

    This action handles MFA authentication for all supported methods:
    - Freja eID (Swedish NIN via NinSessionInfo)
    - BankID (Swedish NIN via BankIDSessionInfo)
    - eIDAS (Foreign identity via ForeignEidSessionInfo)

    NOTE: While this code looks up the user from session.mfa_action.eppn, it doesn't require the user
          to be already logged in, so it can't use the @require_user decorator.

    :param args: ACS action arguments

    :returns: ACS action result
    """
    result = run_mfa_authenticate(
        args,
        common_saml_checks=common_saml_checks,
        get_proofing_functions=get_proofing_functions,
        get_user=lambda: current_app.central_userdb.get_user_by_eppn(session.mfa_action.eppn),
        method_not_available_msg=SamlEidMsg.method_not_available,
        identity_not_matching_msg=SamlEidMsg.identity_not_matching,
        mfa_authn_success_msg=SamlEidMsg.mfa_authn_success,
        app=current_app,
    )
    if result.success:
        assert args.proofing_method is not None
        parsed = args.proofing_method.parse_session_info(args.session_info, backdoor=args.backdoor)
        assert isinstance(parsed.info, BaseSessionInfo)
        current_app.stats.count(name=f"mfa_auth_{parsed.info.issuer}_success")
    return result


@acs_action(SamlEidAcsAction.mfa_register)
def samleid_mfa_register_action(args: ACSArgs) -> ACSResult:
    """Parse a signup-flow external MFA assertion and persist identity + LoA
    on the SP_AuthnRequest. No user yet, no DB write, no proofing log."""
    parsed = parse_mfa_register_args(
        args,
        common_saml_checks=common_saml_checks,
        get_proofing_functions=get_proofing_functions,
        method_not_available_msg=SamlEidMsg.method_not_available,
        app=current_app,
    )
    if isinstance(parsed, ACSResult):
        return parsed
    assert isinstance(parsed, MfaRegisterParsed)  # type narrowing

    match parsed.session_info:
        case NinSessionInfo():
            args.authn_req.external_mfa_signup_identity = ExternalMfaSignupIdentity(
                given_name=parsed.session_info.attributes.given_name,
                surname=parsed.session_info.attributes.surname,
                date_of_birth=datetime.combine(
                    parsed.session_info.attributes.date_of_birth, datetime.min.time(), tzinfo=UTC
                ),
                nin=parsed.session_info.attributes.nin,
                framework=parsed.framework,
                loa=parsed.loa,
            )
        case ForeignEidSessionInfo():
            args.authn_req.external_mfa_signup_identity = ExternalMfaSignupIdentity(
                given_name=parsed.session_info.attributes.given_name,
                surname=parsed.session_info.attributes.surname,
                date_of_birth=datetime.combine(
                    parsed.session_info.attributes.date_of_birth, datetime.min.time(), tzinfo=UTC
                ),
                eidas_prid=parsed.session_info.attributes.prid,
                eidas_prid_persistence=parsed.session_info.attributes.prid_persistence,
                country_code=parsed.session_info.attributes.country_code,
                framework=parsed.framework,
                loa=parsed.loa,
            )
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
            return ACSResult(message=SamlEidMsg.method_not_available)

    return ACSResult(success=True, message=SamlEidMsg.mfa_authn_success)
