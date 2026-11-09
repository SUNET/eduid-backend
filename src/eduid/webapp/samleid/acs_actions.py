from eduid.userdb import User
from eduid.webapp.common.api.decorators import require_user
from eduid.webapp.common.authn.acs_enums import SamlEidAcsAction
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult, acs_action
from eduid.webapp.common.proofing.shared_actions import run_common_saml_checks
from eduid.webapp.common.proofing.swedenconnect.flow import (
    sc_mfa_authenticate,
    sc_mfa_register,
    sc_verify_credential,
    sc_verify_identity,
)
from eduid.webapp.common.session import session
from eduid.webapp.samleid.app import current_samleid_app as current_app
from eduid.webapp.samleid.helpers import SAMLEID_MSGS, SamlEidMsg

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
    return sc_verify_identity(user, args, SAMLEID_MSGS, common_checks=common_saml_checks, app=current_app)


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
    return sc_verify_credential(user, args, SAMLEID_MSGS, common_checks=common_saml_checks, app=current_app)


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
    return sc_mfa_authenticate(
        args,
        SAMLEID_MSGS,
        common_checks=common_saml_checks,
        get_user=lambda: current_app.central_userdb.get_user_by_eppn(session.mfa_action.eppn),
        app=current_app,
    )


@acs_action(SamlEidAcsAction.mfa_register)
def samleid_mfa_register_action(args: ACSArgs) -> ACSResult:
    """Parse a signup-flow external MFA assertion and persist identity + LoA
    on the SP_AuthnRequest. No user yet, no DB write, no proofing log."""
    return sc_mfa_register(args, SAMLEID_MSGS, common_checks=common_saml_checks, app=current_app)
