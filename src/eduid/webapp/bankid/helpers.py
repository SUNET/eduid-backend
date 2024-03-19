import logging
from dataclasses import dataclass
from enum import unique
from typing import Any, Optional

from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.typing import SAMLHttpArgs
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.userdb import User
from eduid.userdb.credentials import FidoCredential
from eduid.userdb.credentials.external import TrustFramework
from eduid.webapp.authn.helpers import credential_used_to_authenticate
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
    # the personalIdentityNumber from BankID does not correspond to a verified nin in the user's account
    identity_not_matching = "bankid.identity_not_matching"
    # The user already has a verified identity
    identity_already_verified = "bankid.identity_already_verified"
    # Successfully verified the identity
    identity_verify_success = "bankid.identity_verify_success"
    # missing redirect URL for mfa authn
    no_redirect_url = "bankid.no_redirect_url"
    # Token not found on the credentials in the user's account
    token_not_found = "bankid.token_not_found"
    # Attribute missing from IdP
    attribute_missing = "bankid.attribute_missing"
    # Unavailable vetting method requested
    method_not_available = "bankid.method_not_available"
    # Need to authenticate (again?) before performing this action
    must_authenticate = "bankid.must_authenticate"
    # Status requested for unknown authn_id
    not_found = "bankid.not_found"
    # Successfully authenticated with external MFA
    mfa_authn_success = "bankid.mfa_authn_success"
    # Successfully verified a credential
    credential_verify_success = "bankid.credential_verify_success"


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
    loa_uris = [current_app.conf.authentication_context_map[loa] for loa in required_loa]
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


@dataclass()
class CredentialVerifyResult:
    verified_ok: bool
    message: Optional[BankIDMsg] = None
    response: Optional[WerkzeugResponse] = None  # TODO: make obsolete and remove
    location: Optional[str] = None


def check_credential_to_verify(user: User, credential_id: str) -> CredentialVerifyResult:
    # Check if requested key id is a mfa token and if the user used that to log in
    token_to_verify = user.credentials.find(credential_id)
    if not isinstance(token_to_verify, FidoCredential):
        current_app.logger.error(f"Credential {token_to_verify} is not a FidoCredential")
        return CredentialVerifyResult(verified_ok=False, message=BankIDMsg.token_not_found)

    # Check if the credential was just now (within 60s) used to log in
    credential_already_used = credential_used_to_authenticate(token_to_verify, max_age=60)
    current_app.logger.debug(f"Credential {credential_id} recently used for login: {credential_already_used}")
    if not credential_already_used:
        # If token was not used for login, ask the user to authenticate again
        current_app.logger.info(f"{token_to_verify.key} was not used to login, returning must authenticate error")
        return CredentialVerifyResult(verified_ok=False, message=BankIDMsg.must_authenticate)

    return CredentialVerifyResult(verified_ok=True)
