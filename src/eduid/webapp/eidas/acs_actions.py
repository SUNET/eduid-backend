from datetime import UTC, datetime

from eduid.common.models.saml_models import BaseSessionInfo
from eduid.userdb import User
from eduid.webapp.common.api.decorators import require_user
from eduid.webapp.common.authn.acs_enums import EidasAcsAction
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
from eduid.webapp.eidas.app import current_eidas_app as current_app
from eduid.webapp.eidas.helpers import EidasMsg
from eduid.webapp.eidas.proofing import get_proofing_functions
from eduid.webapp.eidas.saml_session_info import ForeignEidSessionInfo, NinSessionInfo

__author__ = "lundberg"


def common_saml_checks(args: ACSArgs) -> ACSResult | None:
    """Perform common checks for SAML ACS actions."""
    return run_common_saml_checks(
        args,
        authn_context_mismatch_msg=EidasMsg.authn_context_mismatch,
        authn_instant_too_old_msg=EidasMsg.authn_instant_too_old,
        method_not_available=EidasMsg.method_not_available,
        loa_authn_context_map=current_app.conf.loa_authn_context_map,
    )


@acs_action(EidasAcsAction.verify_identity)
@require_user
def verify_identity_action(user: User, args: ACSArgs) -> ACSResult:
    """Use a Sweden Connect federation IdP assertion to verify a users' identity."""
    return run_verify_identity(
        user,
        args,
        common_saml_checks=common_saml_checks,
        get_proofing_functions=get_proofing_functions,
        method_not_available_msg=EidasMsg.method_not_available,
        identity_verify_success_msg=EidasMsg.identity_verify_success,
        app=current_app,
    )


@acs_action(EidasAcsAction.verify_credential)
@require_user
def verify_credential_action(user: User, args: ACSArgs) -> ACSResult:
    """Use a Sweden Connect federation IdP assertion to person-proof a users' FIDO credential."""
    return run_verify_credential(
        user,
        args,
        common_saml_checks=common_saml_checks,
        get_proofing_functions=get_proofing_functions,
        method_not_available_msg=EidasMsg.method_not_available,
        credential_not_found_msg=EidasMsg.credential_not_found,
        identity_not_matching_msg=EidasMsg.identity_not_matching,
        credential_verify_success_msg=EidasMsg.credential_verify_success,
        app=current_app,
    )


@acs_action(EidasAcsAction.mfa_authenticate)
def mfa_authenticate_action(args: ACSArgs) -> ACSResult:
    """Authenticate a user using a Sweden Connect federation IdP assertion."""
    result = run_mfa_authenticate(
        args,
        common_saml_checks=common_saml_checks,
        get_proofing_functions=get_proofing_functions,
        get_user=lambda: current_app.central_userdb.get_user_by_eppn(session.mfa_action.eppn),
        method_not_available_msg=EidasMsg.method_not_available,
        identity_not_matching_msg=EidasMsg.identity_not_matching,
        mfa_authn_success_msg=EidasMsg.mfa_authn_success,
        app=current_app,
    )
    if result.success:
        assert args.proofing_method is not None
        parsed = args.proofing_method.parse_session_info(args.session_info, backdoor=args.backdoor)
        assert isinstance(parsed.info, BaseSessionInfo)
        current_app.stats.count(name=f"mfa_auth_{parsed.info.issuer}_success")
    return result


@acs_action(EidasAcsAction.mfa_register)
def mfa_register_action(args: ACSArgs) -> ACSResult:
    """Parse the external MFA assertion for a signup-flow authn and persist
    identity + LoA on the SP_AuthnRequest.

    No user exists yet, no DB write, no proofing log. The signup backend
    reads ``args.authn_req.external_mfa_signup_identity`` later.
    """
    parsed = parse_mfa_register_args(
        args,
        common_saml_checks=common_saml_checks,
        get_proofing_functions=get_proofing_functions,
        method_not_available_msg=EidasMsg.method_not_available,
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
        case _:
            current_app.logger.error(f"Unsupported session info type: {type(parsed.session_info)}")
            return ACSResult(message=EidasMsg.method_not_available)

    return ACSResult(success=True, message=EidasMsg.mfa_authn_success)
