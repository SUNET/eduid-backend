from datetime import UTC, datetime

from eduid.userdb import User
from eduid.webapp.common.api.decorators import require_user
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult, acs_action
from eduid.webapp.common.proofing.mfa_signup import parse_mfa_register_args
from eduid.webapp.common.proofing.shared_actions import run_verify_credential, run_verify_identity
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import ExternalMfaSignupIdentity
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
        app_name=current_app.conf.app_name,
        config=current_app.conf,
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
        app_name=current_app.conf.app_name,
        config=current_app.conf,
    )


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
        app_name=current_app.conf.app_name,
        config=current_app.conf,
    )
    if isinstance(parsed, ACSResult):
        return parsed

    match parsed.session_info:
        case FrejaEIDDocumentUserInfo():
            if parsed.session_info.personal_identity_number is not None:
                # Swedish NIN identity
                args.authn_req.external_mfa_signup_identity = ExternalMfaSignupIdentity(
                    given_name=parsed.session_info.given_name,
                    surname=parsed.session_info.family_name,
                    date_of_birth=datetime.combine(parsed.session_info.date_of_birth, datetime.min.time(), tzinfo=UTC),
                    nin=parsed.session_info.personal_identity_number,
                    framework=parsed.framework,
                    loa=parsed.loa,
                )
            else:
                # Foreign passport — Freja foreign identity
                args.authn_req.external_mfa_signup_identity = ExternalMfaSignupIdentity(
                    given_name=parsed.session_info.given_name,
                    surname=parsed.session_info.family_name,
                    date_of_birth=datetime.combine(parsed.session_info.date_of_birth, datetime.min.time(), tzinfo=UTC),
                    freja_user_id=parsed.session_info.user_id,
                    country_code=parsed.session_info.document.country,
                    freja_registration_level=parsed.session_info.registration_level,
                    freja_loa_level=parsed.session_info.loa_level,
                    framework=parsed.framework,
                    loa=parsed.loa,
                )
        case _:
            current_app.logger.error(f"Unsupported session info type: {type(parsed.session_info)}")
            return ACSResult(message=FrejaEIDMsg.method_not_available)

    return ACSResult(success=True, message=FrejaEIDMsg.mfa_authn_success)
