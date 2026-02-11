from eduid.common.models.saml_models import BaseSessionInfo, SAMLAttributes
from eduid.webapp.bankid.saml_session_info import BankIDSessionInfo
from eduid.webapp.bankid.saml_session_info import NinAttributes as BankIDNinAttributes
from eduid.webapp.eidas.saml_session_info import ForeignEidAttributes, ForeignEidSessionInfo, NinSessionInfo
from eduid.webapp.eidas.saml_session_info import NinAttributes as EidasNinAttributes

__author__ = "lundberg"

__all__ = [
    "BaseSessionInfo",
    "SAMLAttributes",
    "BankIDSessionInfo",
    "BankIDNinAttributes",
    "ForeignEidSessionInfo",
    "ForeignEidAttributes",
    "NinSessionInfo",
    "EidasNinAttributes",
]
