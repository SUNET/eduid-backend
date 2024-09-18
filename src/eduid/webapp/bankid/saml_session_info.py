from pydantic import Field

from eduid.common.models.saml_models import BaseSessionInfo, SAMLAttributes

__author__ = "lundberg"


class NinAttributes(SAMLAttributes):
    nin: str = Field(alias="personalIdentityNumber")
    given_name: str = Field(alias="givenName")
    surname: str = Field(alias="sn")
    display_name: str | None = Field(default=None, alias="displayName")
    auth_context_params: str = Field(alias="authContextParams")
    transaction_id: str = Field(alias="transactionIdentifier")


class BankIDSessionInfo(BaseSessionInfo):
    attributes: NinAttributes = Field(alias="ava")
