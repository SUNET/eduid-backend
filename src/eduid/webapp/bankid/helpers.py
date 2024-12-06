import logging
from enum import unique
from typing import Any

from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.typing import SAMLHttpArgs

from eduid.userdb.credentials.external import TrustFramework
from eduid.webapp.bankid.app import current_bankid_app as current_app
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.authn.cache import OutstandingQueriesCache
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import AuthnRequestRef

__author__ = "lundberg"

logger = logging.getLogger(__name__)


@unique
class BankIDMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # uncertified LOA 3 not asserted
    authn_context_mismatch = "bankid.authn_context_mismatch"
    # Authentication instant too old
    authn_instant_too_old = "bankid.authn_instant_too_old"
    # the personalIdentityNumber from BankID does not correspond to a verified nin in the user's account
    identity_not_matching = "bankid.identity_not_matching"
    # The user already has a verified identity
    identity_already_verified = "bankid.identity_already_verified"
    # Successfully verified the identity
    identity_verify_success = "bankid.identity_verify_success"
    # missing redirect URL for mfa authn
    no_redirect_url = "bankid.no_redirect_url"
    # Attribute missing from IdP
    attribute_missing = "bankid.attribute_missing"
    # Unavailable vetting method requested
    method_not_available = "bankid.method_not_available"
    # Status requested for unknown authn_id
    not_found = "bankid.not_found"
    # Successfully authenticated with external MFA
    mfa_authn_success = "bankid.mfa_authn_success"
    # Successfully verified a credential
    credential_verify_success = "bankid.credential_verify_success"
    # frontend action is not implemented
    frontend_action_not_supported = "bankid.frontend_action_not_supported"
    # Credential not found in the user's account
    credential_not_found = "bankid.credential_not_found"


def create_authn_info(
    authn_ref: AuthnRequestRef,
    framework: TrustFramework,
    selected_idp: str,
    required_loa: list[str],
    force_authn: bool = False,
) -> SAMLHttpArgs:
    if framework not in [TrustFramework.BANKID]:
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

    oq_cache = OutstandingQueriesCache(session.bankid.sp.pysaml2_dicts)
    oq_cache.set(session_id, authn_ref)
    return info
