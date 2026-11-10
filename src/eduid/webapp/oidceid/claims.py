"""
OIDC specific helpers for the oidceid app: what to ask the OpenID Provider for, and how to turn the
claims in the ID token into the same SessionInfo structure samleid gets from a SAML assertion.

No Flask here. Claim names are from the Sweden Connect specs:
- Swedish OIDC Claims Specification 1.0 (https://id.oidc.se/claim/*, https://id.oidc.se/scope/*)
- OIDC Claims and Scopes Specification for Sweden Connect 1.1 (https://id.swedenconnect.se/*)
- OIDC Profile for Sweden Connect (https://id.oidc.se/param/authnProvider)
"""

import json
import logging
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.proofing.methods import ProofingMethods
from eduid.webapp.oidceid.settings.common import OidcEidConfig

__author__ = "lundberg"

logger = logging.getLogger(__name__)

# Claims
CLAIM_PERSONAL_IDENTITY_NUMBER = "https://id.oidc.se/claim/personalIdentityNumber"
CLAIM_COORDINATION_NUMBER = "https://id.oidc.se/claim/coordinationNumber"
CLAIM_PRID = "https://id.swedenconnect.se/claim/prid"
CLAIM_PRID_PERSISTENCE = "https://id.swedenconnect.se/claim/pridPersistence"
CLAIM_EIDAS_PERSON_IDENTIFIER = "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier"
CLAIM_EIDAS_COUNTRY = "https://id.swedenconnect.se/claim/eidasCountry"
CLAIM_MAPPED_PERSONAL_IDENTITY_NUMBER = "https://id.swedenconnect.se/claim/mappedPersonalIdentityNumber"
# Standard claims (OpenID Core, RFC 8417 for txn)
CLAIM_GIVEN_NAME = "given_name"
CLAIM_FAMILY_NAME = "family_name"
CLAIM_BIRTHDATE = "birthdate"
CLAIM_NAME = "name"
CLAIM_TXN = "txn"

# Scopes
SCOPE_NATURAL_PERSON_NUMBER = "https://id.oidc.se/scope/naturalPersonNumber"
SCOPE_NATURAL_PERSON_INFO = "https://id.oidc.se/scope/naturalPersonInfo"
SCOPE_EIDAS_NATURAL_PERSON_IDENTITY = "https://id.swedenconnect.se/scope/eidasNaturalPersonIdentity"

# Request parameter understood by proxy OPs
PARAM_AUTHN_PROVIDER = "https://id.oidc.se/param/authnProvider"

_ESSENTIAL: dict[str, bool] = {"essential": True}


def _id_token_claims(method: ProofingMethods) -> dict[str, dict[str, bool] | None]:
    """The identity claims to request in the ID token, None means requested but not essential."""
    match method:
        case ProofingMethods.FREJA:
            return {
                CLAIM_PERSONAL_IDENTITY_NUMBER: None,
                CLAIM_COORDINATION_NUMBER: None,
                CLAIM_GIVEN_NAME: _ESSENTIAL,
                CLAIM_FAMILY_NAME: _ESSENTIAL,
                CLAIM_BIRTHDATE: _ESSENTIAL,
                CLAIM_NAME: None,
            }
        case ProofingMethods.EIDAS:
            return {
                CLAIM_PRID: _ESSENTIAL,
                CLAIM_PRID_PERSISTENCE: _ESSENTIAL,
                CLAIM_EIDAS_PERSON_IDENTIFIER: _ESSENTIAL,
                CLAIM_GIVEN_NAME: _ESSENTIAL,
                CLAIM_FAMILY_NAME: _ESSENTIAL,
                CLAIM_BIRTHDATE: _ESSENTIAL,
                CLAIM_EIDAS_COUNTRY: _ESSENTIAL,
                CLAIM_TXN: _ESSENTIAL,
                CLAIM_MAPPED_PERSONAL_IDENTITY_NUMBER: None,
            }
        case _:
            raise ValueError(f"Unsupported proofing method for oidceid: {method}")


def scopes_for_method(method: ProofingMethods) -> list[str]:
    """The scopes to request for a proofing method."""
    match method:
        case ProofingMethods.FREJA:
            return ["openid", SCOPE_NATURAL_PERSON_NUMBER, SCOPE_NATURAL_PERSON_INFO]
        case ProofingMethods.EIDAS:
            return ["openid", SCOPE_EIDAS_NATURAL_PERSON_IDENTITY, SCOPE_NATURAL_PERSON_INFO]
        case _:
            raise ValueError(f"Unsupported proofing method for oidceid: {method}")


def build_authn_params(
    method: ProofingMethods, required_loa: Sequence[str], conf: OidcEidConfig, force_authn: bool
) -> dict[str, str]:
    """
    Build the extra authorization request parameters for a proofing method.

    The requested authentication context goes into an essential `acr` claim, the same URIs samleid requests,
    acr_values is never used.

    :param method: The proofing method
    :param required_loa: Names of the accepted LOAs, mapped to URIs with conf.loa_authn_context_map
    :param conf: App config
    :param force_authn: Force re-authentication (prompt=login)
    :returns: Parameters to pass as extra_params when minting the authorization request
    """
    acr_values = [conf.loa_authn_context_map[loa] for loa in required_loa]
    id_token: dict[str, dict[str, Any] | None] = {
        "acr": {"essential": True, "values": acr_values},
        "auth_time": {"essential": True},
    }
    id_token.update(_id_token_claims(method))
    params: dict[str, str] = {"claims": json.dumps({"id_token": id_token})}
    if force_authn:
        params["prompt"] = "login"
    authn_provider = conf.method_authn_provider.get(method.value)
    if authn_provider:
        params[PARAM_AUTHN_PROVIDER] = authn_provider
    return params


def _auth_time_iso(auth_time: object) -> str | None:
    # bool is an int subclass, but never a timestamp
    if isinstance(auth_time, bool) or not isinstance(auth_time, int | float):
        return None
    try:
        return datetime.fromtimestamp(auth_time, tz=UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _put(ava: dict[str, list[str]], name: str, claims: Mapping[str, Any], *claim_names: str) -> None:
    """Set a SAML style attribute from the first present, non-empty claim."""
    for claim_name in claim_names:
        value = claims.get(claim_name)
        if isinstance(value, str) and value:
            ava[name] = [value]
            return


def claims_to_session_info(claims: Mapping[str, Any], *, method: ProofingMethods) -> SessionInfo | None:
    """
    Convert ID token claims into the SessionInfo structure a SAML assertion would have produced.

    Missing identity attributes are omitted, never invented (no birthdate from the personnummer), so the
    normal session info parsing reports them as missing attributes.

    :param claims: Verified claims (ID token and optionally userinfo)
    :param method: The proofing method
    :returns: SessionInfo, or None if the acr or auth_time claim is missing
    """
    acr = claims.get("acr")
    auth_time = _auth_time_iso(claims.get("auth_time"))
    issuer = claims.get("iss")
    if not isinstance(acr, str) or not acr or auth_time is None or not isinstance(issuer, str):
        return None

    ava: dict[str, list[str]] = {}
    _put(ava, "givenName", claims, CLAIM_GIVEN_NAME)
    _put(ava, "sn", claims, CLAIM_FAMILY_NAME)
    _put(ava, "dateOfBirth", claims, CLAIM_BIRTHDATE)
    match method:
        case ProofingMethods.FREJA:
            # Coordination numbers map to the NIN, like in samleid
            _put(ava, "personalIdentityNumber", claims, CLAIM_PERSONAL_IDENTITY_NUMBER, CLAIM_COORDINATION_NUMBER)
            _put(ava, "displayName", claims, CLAIM_NAME)
        case ProofingMethods.EIDAS:
            _put(ava, "prid", claims, CLAIM_PRID)
            _put(ava, "pridPersistence", claims, CLAIM_PRID_PERSISTENCE)
            _put(ava, "eidasPersonIdentifier", claims, CLAIM_EIDAS_PERSON_IDENTIFIER)
            _put(ava, "c", claims, CLAIM_EIDAS_COUNTRY)
            _put(ava, "transactionIdentifier", claims, CLAIM_TXN)
            _put(ava, "mappedPersonalIdentityNumber", claims, CLAIM_MAPPED_PERSONAL_IDENTITY_NUMBER)
        case _:
            raise ValueError(f"Unsupported proofing method for oidceid: {method}")

    return SessionInfo({"issuer": issuer, "authn_info": [(acr, [], auth_time)], "ava": ava})
