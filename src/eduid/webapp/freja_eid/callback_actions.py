from datetime import UTC, datetime

from iso3166 import countries

from eduid.userdb import User
from eduid.webapp.common.api.decorators import require_user
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult, acs_action
from eduid.webapp.common.proofing.mfa_signup import parse_mfa_register_args
from eduid.webapp.common.proofing.shared_actions import run_mfa_authenticate, run_verify_credential, run_verify_identity
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import (
    ExternalMfaSignupFrejaEIDForeignIdentity,
    ExternalMfaSignupFrejaEIDIdentity,
)
from eduid.webapp.freja_eid.app import current_freja_eid_app as current_app
from eduid.webapp.freja_eid.callback_enums import FrejaEIDAction
from eduid.webapp.freja_eid.helpers import FrejaEIDDocumentUserInfo, FrejaEIDMsg
from eduid.webapp.freja_eid.proofing import get_proofing_functions

__author__ = "lundberg"


@acs_action(FrejaEIDAction.verify_identity)
@require_user
def verify_identity_action(user: User, args: ACSArgs) -> ACSResult:
    """Use a Freja OIDC userinfo to verify a users' identity."""
    return run_verify_identity(
        user,
        args,
        common_saml_checks=None,
        get_proofing_functions=get_proofing_functions,
        method_not_available_msg=FrejaEIDMsg.method_not_available,
        identity_verify_success_msg=FrejaEIDMsg.identity_verify_success,
        app=current_app,
    )


@acs_action(FrejaEIDAction.verify_credential)
@require_user
def verify_credential_action(user: User, args: ACSArgs) -> ACSResult:
    """Use a Freja eID assertion to person-proof a users' FIDO credential."""
    return run_verify_credential(
        user,
        args,
        common_saml_checks=None,
        get_proofing_functions=get_proofing_functions,
        method_not_available_msg=FrejaEIDMsg.method_not_available,
        credential_not_found_msg=FrejaEIDMsg.credential_not_found,
        identity_not_matching_msg=FrejaEIDMsg.identity_not_matching,
        credential_verify_success_msg=FrejaEIDMsg.credential_verify_success,
        app=current_app,
    )


@acs_action(FrejaEIDAction.mfa_authenticate)
def mfa_authenticate_action(args: ACSArgs) -> ACSResult:
    """Authenticate a user using Freja eID."""
    result = run_mfa_authenticate(
        args,
        common_saml_checks=None,
        get_proofing_functions=get_proofing_functions,
        get_user=lambda: current_app.central_userdb.get_user_by_eppn(session.mfa_action.eppn),
        method_not_available_msg=FrejaEIDMsg.method_not_available,
        identity_not_matching_msg=FrejaEIDMsg.identity_not_matching,
        mfa_authn_success_msg=FrejaEIDMsg.mfa_authn_success,
        app=current_app,
    )
    if result.success:
        current_app.stats.count(name="mfa_auth_freja_eid_success")
    return result


@acs_action(FrejaEIDAction.mfa_register)
def mfa_register_action(args: ACSArgs) -> ACSResult:
    """Parse a signup-flow external MFA Freja eID userinfo and persist identity
    + LoA on the RP_AuthnRequest. No user yet, no DB write, no proofing log.
    """
    parsed = parse_mfa_register_args(
        args,
        common_saml_checks=None,  # OIDC — no SAML-level checks
        get_proofing_functions=get_proofing_functions,
        method_not_available_msg=FrejaEIDMsg.method_not_available,
        app=current_app,
    )
    if isinstance(parsed, ACSResult):
        return parsed

    match parsed.session_info:
        case FrejaEIDDocumentUserInfo():
            issuing_country = countries.get(parsed.session_info.document.country, None)
            sweden = countries.get("SE")
            if issuing_country is not None and sweden is not None and issuing_country == sweden:
                # Swedish NIN identity
                if parsed.session_info.personal_identity_number is None:
                    current_app.logger.debug(f"{parsed=}")
                    current_app.logger.error("personal_identity_number missing for Swedish document")
                    return ACSResult(message=FrejaEIDMsg.method_not_available)
                args.authn_req.external_mfa_signup_identity = ExternalMfaSignupFrejaEIDIdentity(
                    date_of_birth=datetime.combine(parsed.session_info.date_of_birth, datetime.min.time(), tzinfo=UTC),
                    document_number=parsed.session_info.document.serial_number,
                    document_type=parsed.session_info.document.type.value,
                    framework=parsed.framework,
                    given_name=parsed.session_info.given_name,
                    issuer=parsed.session_info.iss,
                    loa=parsed.loa,
                    loa_level=parsed.session_info.loa_level,
                    nin=parsed.session_info.personal_identity_number,
                    registration_level=parsed.session_info.registration_level,
                    surname=parsed.session_info.family_name,
                    transaction_id=parsed.session_info.transaction_id,
                    user_id=parsed.session_info.user_id,
                )
            else:
                # Foreign passport — Freja foreign identity
                args.authn_req.external_mfa_signup_identity = ExternalMfaSignupFrejaEIDForeignIdentity(
                    country_code=parsed.session_info.document.country,
                    date_of_birth=datetime.combine(parsed.session_info.date_of_birth, datetime.min.time(), tzinfo=UTC),
                    document_number=parsed.session_info.document.serial_number,
                    document_type=parsed.session_info.document.type.value,
                    framework=parsed.framework,
                    given_name=parsed.session_info.given_name,
                    issuer=parsed.session_info.iss,
                    issuing_country=parsed.session_info.document.country,
                    loa=parsed.loa,
                    loa_level=parsed.session_info.loa_level,
                    personal_identity_number=parsed.session_info.personal_identity_number
                    or "freja_no_identity_number_provided",
                    registration_level=parsed.session_info.registration_level,
                    surname=parsed.session_info.family_name,
                    transaction_id=parsed.session_info.transaction_id,
                    user_id=parsed.session_info.user_id,
                )
        case _:
            current_app.logger.error(f"Unsupported session info type: {type(parsed.session_info)}")
            return ACSResult(message=FrejaEIDMsg.method_not_available)

    return ACSResult(success=True, message=FrejaEIDMsg.mfa_authn_success)
