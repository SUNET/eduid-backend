import logging
from enum import unique
from typing import Any

from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.typing import SAMLHttpArgs

from eduid.userdb.credentials.external import TrustFramework
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.authn.cache import OutstandingQueriesCache
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import AuthnRequestRef
from eduid.webapp.samleid.app import current_samleid_app as current_app

__author__ = "lundberg"

logger = logging.getLogger(__name__)


@unique
class SamlEidMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.

    This enum combines messages from both EidasMsg and BankIDMsg into a unified
    set for the samleid app which handles all SAML-based identity proofing.
    """

    # LOA not matching expected level
    authn_context_mismatch = "samleid.authn_context_mismatch"
    # Authentication instant too old
    authn_instant_too_old = "samleid.authn_instant_too_old"
    # the frontend action is not supported
    frontend_action_not_supported = "samleid.frontend_action_not_supported"
    # the identity from the IdP does not correspond to a verified identity in the user's account
    identity_not_matching = "samleid.identity_not_matching"
    # The user already has a verified identity
    identity_already_verified = "samleid.identity_already_verified"
    # Successfully verified the identity
    identity_verify_success = "samleid.identity_verify_success"
    # missing redirect URL for mfa authn
    no_redirect_url = "samleid.no_redirect_url"
    # Credential not found in the user's account
    credential_not_found = "samleid.credential_not_found"
    # Attribute missing from IdP
    attribute_missing = "samleid.attribute_missing"
    # Unavailable vetting method requested
    method_not_available = "samleid.method_not_available"
    # Status requested for unknown authn_id
    not_found = "samleid.not_found"
    # Successfully authenticated with external MFA
    mfa_authn_success = "samleid.mfa_authn_success"
    # Successfully verified a credential
    credential_verify_success = "samleid.credential_verify_success"
    # Credential verification not allowed (toggle for eidas credential verification)
    credential_verification_not_allowed = "samleid.credential_verification_not_allowed"


def create_authn_info(
    authn_ref: AuthnRequestRef,
    framework: TrustFramework,
    selected_idp: str,
    required_loa: list[str],
    force_authn: bool = False,
) -> SAMLHttpArgs:
    """
    Create SAML authentication info for initiating authentication.

    :param authn_ref: Reference for the authentication request
    :param framework: Trust framework being used (SWECONN, EIDAS, BANKID)
    :param selected_idp: Entity ID of the IdP to authenticate with
    :param required_loa: List of required Level of Assurance values
    :param force_authn: Whether to force re-authentication
    :returns: SAML HTTP arguments for the authentication request
    """
    if framework not in [TrustFramework.SWECONN, TrustFramework.EIDAS, TrustFramework.BANKID]:
        raise ValueError(f"Unrecognised trust framework: {framework}")

    kwargs: dict[str, Any] = {
        "force_authn": str(force_authn).lower(),
    }

    # LOA
    logger.debug(f"Requesting AuthnContext {required_loa}")
    loa_uris = [current_app.conf.loa_authn_context_map[loa] for loa in required_loa]
    kwargs["requested_authn_context"] = {"authn_context_class_ref": loa_uris, "comparison": "exact"}

    client = Saml2Client(current_app.saml2_config)
    try:
        session_id, info = client.prepare_for_authenticate(
            entityid=selected_idp,
            relay_state=authn_ref,
            binding=BINDING_HTTP_REDIRECT,
            sigalg=current_app.conf.authn_sign_alg,
            digest_alg=current_app.conf.authn_digest_alg,
            **kwargs,
        )
    except TypeError:
        logger.error("Unable to know which IdP to use")
        raise

    oq_cache = OutstandingQueriesCache(session.samleid.sp.pysaml2_dicts)
    oq_cache.set(session_id, authn_ref)
    return info
