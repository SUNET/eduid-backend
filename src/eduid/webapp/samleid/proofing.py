"""
Unified proofing dispatch for the samleid webapp.

This module provides a factory/dispatcher to select the appropriate proofing
functions based on the authentication method (freja, bankid, or eidas).
"""

from eduid.common.config.base import ProofingConfigMixin
from eduid.common.models.saml_models import BaseSessionInfo
from eduid.webapp.bankid.proofing import BankIDProofingFunctions
from eduid.webapp.bankid.saml_session_info import BankIDSessionInfo
from eduid.webapp.common.proofing.base import ProofingFunctions
from eduid.webapp.eidas.proofing import EidasProofingFunctions, FrejaProofingFunctions
from eduid.webapp.eidas.saml_session_info import ForeignEidSessionInfo, NinSessionInfo

__author__ = "lundberg"


class UnsupportedMethod(Exception):
    """Raised when an unsupported proofing method is requested."""


def get_proofing_functions(
    session_info: BaseSessionInfo,
    app_name: str,
    config: ProofingConfigMixin,
    backdoor: bool,
) -> ProofingFunctions:
    """
    Get the appropriate proofing functions based on session info type.

    The session info type determines which proofing functions to use:
    - NinSessionInfo -> FrejaProofingFunctions (Swedish NIN via Freja)
    - BankIDSessionInfo -> BankIDProofingFunctions (Swedish NIN via BankID)
    - ForeignEidSessionInfo -> EidasProofingFunctions (Foreign identity via eIDAS)

    :param session_info: The parsed SAML session info from the IdP
    :param app_name: Name of the application for proofing logs
    :param config: Configuration with proofing settings
    :param backdoor: Whether backdoor/test mode is enabled
    :returns: The appropriate proofing functions instance
    :raises UnsupportedMethod: If the session info type is not supported
    """
    if isinstance(session_info, NinSessionInfo):
        return FrejaProofingFunctions(
            session_info=session_info,
            app_name=app_name,
            config=config,
            backdoor=backdoor,
        )
    elif isinstance(session_info, BankIDSessionInfo):
        return BankIDProofingFunctions(
            session_info=session_info,
            app_name=app_name,
            config=config,
            backdoor=backdoor,
        )
    elif isinstance(session_info, ForeignEidSessionInfo):
        return EidasProofingFunctions(
            session_info=session_info,
            app_name=app_name,
            config=config,
            backdoor=backdoor,
        )
    else:
        raise UnsupportedMethod(f"Proofing functions for {type(session_info).__name__} not implemented")
