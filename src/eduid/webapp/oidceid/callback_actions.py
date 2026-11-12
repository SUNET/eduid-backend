from eduid.userdb import User
from eduid.webapp.common.api.decorators import require_user
from eduid.webapp.common.authn.acs_enums import OidcEidAcsAction
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult, acs_action
from eduid.webapp.common.proofing.shared_actions import run_common_saml_checks
from eduid.webapp.common.proofing.swedenconnect.flow import (
    sc_mfa_authenticate,
    sc_mfa_register,
    sc_verify_credential,
    sc_verify_identity,
)
from eduid.webapp.common.session import session
from eduid.webapp.oidceid.app import current_oidceid_app as current_app
from eduid.webapp.oidceid.helpers import OIDCEID_MSGS, OidcEidMsg

__author__ = "lundberg"


def common_checks(args: ACSArgs) -> ACSResult | None:
    """
    The assurance level and authn instant checks, the same as samleid does for a SAML assertion.

    The OIDC claims are converted to the SAML style SessionInfo before the actions run, so the same checks apply.
    """
    return run_common_saml_checks(
        args,
        authn_context_mismatch_msg=OidcEidMsg.authn_context_mismatch,
        authn_instant_too_old_msg=OidcEidMsg.authn_instant_too_old,
        method_not_available=OidcEidMsg.method_not_available,
        loa_authn_context_map=current_app.conf.loa_authn_context_map,
    )


@acs_action(OidcEidAcsAction.verify_identity)
@require_user
def oidceid_verify_identity_action(user: User, args: ACSArgs) -> ACSResult:
    """Use the claims from an OpenID Provider to verify a user's identity (Freja eID or eIDAS)."""
    return sc_verify_identity(user, args, OIDCEID_MSGS, common_checks=common_checks, app=current_app)


@acs_action(OidcEidAcsAction.verify_credential)
@require_user
def oidceid_verify_credential_action(user: User, args: ACSArgs) -> ACSResult:
    """
    Use the claims from an OpenID Provider to person-proof a user's FIDO credential.

    If the user doesn't have a verified identity for this method, their identity is verified as part of this.
    """
    return sc_verify_credential(user, args, OIDCEID_MSGS, common_checks=common_checks, app=current_app)


@acs_action(OidcEidAcsAction.mfa_authenticate)
def oidceid_mfa_authenticate_action(args: ACSArgs) -> ACSResult:
    """
    Authenticate a user using the claims from an OpenID Provider for multi-factor authentication.

    NOTE: While this code looks up the user from session.mfa_action.eppn, it doesn't require the user
          to be already logged in, so it can't use the @require_user decorator.
    """
    return sc_mfa_authenticate(
        args,
        OIDCEID_MSGS,
        common_checks=common_checks,
        get_user=lambda: current_app.central_userdb.get_user_by_eppn(session.mfa_action.eppn),
        app=current_app,
    )


@acs_action(OidcEidAcsAction.mfa_register)
def oidceid_mfa_register_action(args: ACSArgs) -> ACSResult:
    """Parse a signup-flow external MFA response and persist identity + LoA on the authn request."""
    return sc_mfa_register(args, OIDCEID_MSGS, common_checks=common_checks, app=current_app)
