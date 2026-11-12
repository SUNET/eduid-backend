from enum import unique

from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.proofing.swedenconnect.flow import SwedenConnectMsgs

__author__ = "lundberg"


@unique
class OidcEidMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.

    Same members as the samleid messages, with an additional pair for OIDC specific failures.
    """

    # LOA not matching expected level
    authn_context_mismatch = "oidceid.authn_context_mismatch"
    # Authentication instant too old
    authn_instant_too_old = "oidceid.authn_instant_too_old"
    # the frontend action is not supported
    frontend_action_not_supported = "oidceid.frontend_action_not_supported"
    # the identity from the OP does not correspond to a verified identity in the user's account
    identity_not_matching = "oidceid.identity_not_matching"
    # The user already has a verified identity
    identity_already_verified = "oidceid.identity_already_verified"
    # Successfully verified the identity
    identity_verify_success = "oidceid.identity_verify_success"
    # missing redirect URL for mfa authn
    no_redirect_url = "oidceid.no_redirect_url"
    # Credential not found in the user's account
    credential_not_found = "oidceid.credential_not_found"
    # Attribute missing from OP
    attribute_missing = "oidceid.attribute_missing"
    # Unavailable vetting method requested
    method_not_available = "oidceid.method_not_available"
    # Status requested for unknown authn_id
    not_found = "oidceid.not_found"
    # Successfully authenticated with external MFA
    mfa_authn_success = "oidceid.mfa_authn_success"
    # Successfully verified a credential
    credential_verify_success = "oidceid.credential_verify_success"
    # Credential verification not allowed (toggle for eidas credential verification)
    credential_verification_not_allowed = "oidceid.credential_verification_not_allowed"
    # The authentication request could not be created or sent to the OP
    authn_request_failed = "oidceid.authn_request_failed"
    # The OP returned an authorization error (user cancelled, access denied, ...)
    authorization_error = "oidceid.authorization_error"


OIDCEID_MSGS = SwedenConnectMsgs(
    authn_context_mismatch=OidcEidMsg.authn_context_mismatch,
    authn_instant_too_old=OidcEidMsg.authn_instant_too_old,
    method_not_available=OidcEidMsg.method_not_available,
    identity_verify_success=OidcEidMsg.identity_verify_success,
    credential_not_found=OidcEidMsg.credential_not_found,
    identity_not_matching=OidcEidMsg.identity_not_matching,
    credential_verify_success=OidcEidMsg.credential_verify_success,
    mfa_authn_success=OidcEidMsg.mfa_authn_success,
    frontend_action_not_supported=OidcEidMsg.frontend_action_not_supported,
    credential_verification_not_allowed=OidcEidMsg.credential_verification_not_allowed,
)
