import logging
from typing import Optional

from eduid.userdb.credentials import Credential, FidoCredential
from eduid.userdb.credentials.external import BankIDCredential, SwedenConnectCredential
from eduid.userdb.idp.user import IdPUser
from eduid.webapp.common.session.namespaces import OnetimeCredential, OnetimeCredType
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
        credential: Optional[Credential]
        if cred_key in ticket.pending_request.onetime_credentials:
            credential = ticket.pending_request.onetime_credentials[cred_key]
        else:
            credential = user.credentials.find(cred_key)
        if isinstance(credential, OnetimeCredential):
            # OLD way
            if credential.type == OnetimeCredType.external_mfa:
                logger.debug(f"User has authenticated using external MFA for this request: {credential}")
                return False
        elif isinstance(credential, SwedenConnectCredential):
            # NEW way
            if credential.level == "loa3":
                logger.debug(f"User has authenticated using external MFA for this request: {credential}")
                return False
        elif isinstance(credential, BankIDCredential):
            # NEW way
            if credential.level == "uncertified-loa3":
                logger.debug(f"User has authenticated using external MFA for this request: {credential}")
                return False
        elif isinstance(credential, FidoCredential):
            logger.debug(f"User has authenticated with a FIDO credential for this request: {credential}")
            return False

    logger.debug("User has one or more FIDO credentials registered, but haven't provided any MFA for this request")
    return True
