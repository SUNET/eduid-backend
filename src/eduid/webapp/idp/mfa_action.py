import logging

from eduid.userdb.credentials import FidoCredential
from eduid.userdb.credentials.external import (
    BankIDCredential,
    EidasCredential,
    FrejaCredential,
    SwedenConnectCredential,
)
from eduid.userdb.idp.user import IdPUser
from eduid.webapp.idp.login_context import LoginContext

__author__ = "ft"

logger = logging.getLogger(__name__)


def need_security_key(user: IdPUser, ticket: LoginContext) -> bool:
    """Check if the user needs to use a Security Key for this very request, regardless of authnContextClassRef"""
    tokens = user.credentials.filter(FidoCredential)
    if not tokens:
        logger.debug("User has no FIDO credentials, no extra requirement for MFA this session imposed")
        return False

    if user.preferences.always_use_security_key is False:
        logger.debug("User has not forced MFA, no extra requirement for MFA this session imposed")
        return False

    for cred_key in ticket.pending_request.credentials_used:
        credential = user.credentials.find(cred_key)
        match credential:
            case FidoCredential():
                logger.debug(f"User has authenticated with a FIDO credential for this request: {credential}")
                return False
            case SwedenConnectCredential():
                if credential.level == "loa3":
                    logger.debug(f"User has authenticated using external MFA for this request: {credential}")
                    return False
            case EidasCredential():
                if credential.level in ["eidas-nf-sub", "eidas-nf-high"]:
                    logger.debug(f"User has authenticated using external MFA for this request: {credential}")
                    return False
            case BankIDCredential():
                if credential.level == "uncertified-loa3":
                    logger.debug(f"User has authenticated using external MFA for this request: {credential}")
                    return False
            case FrejaCredential():
                if credential.level in ["freja-loa3", "freja-loa3_nr"]:
                    logger.debug(f"User has authenticated using external MFA for this request: {credential}")
                    return False

    logger.debug("User has one or more FIDO credentials registered, but haven't provided any MFA for this request")
    return True
