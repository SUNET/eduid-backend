import logging
from datetime import date
from enum import unique
from typing import Any, Optional

from iso3166 import countries
from pydantic import BaseModel, ConfigDict, Field, field_validator

from eduid.userdb.identity import FrejaRegistrationLevel
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.session import session

__author__ = "lundberg"


logger = logging.getLogger(__name__)


@unique
class FrejaEIDMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # failed to create authn request
    authn_request_failed = "freja_eid.authn_request_failed"
    # Unavailable vetting method requested
    method_not_available = "freja_eid.method_not_available"
    # Identity verification success
    identity_verify_success = "freja_eid.identity_verify_success"
    # Authorization error at Svipe ID
    authorization_error = "freja_eid.authorization_fail"
    frontend_action_not_supported = "freja_eid.frontend-action-not-supported"


class SessionOAuthCache:
    @staticmethod
    def get(key: str) -> Any:
        logger.debug(f"Getting {key} from session.freja_eid.oauth_cache")
        return session.freja_eid.rp.authlib_cache.get(key)

    @staticmethod
    def set(key: str, value: Any, expires: Optional[int] = None) -> None:
        session.freja_eid.rp.authlib_cache[key] = value
        logger.debug(f"Set {key}={value} (expires={expires}) in session.freja_eid.oauth_cache")

    @staticmethod
    def delete(key: str) -> None:
        del session.freja_eid.rp.authlib_cache[key]
        logger.debug(f"Deleted {key} from session.freja_eid.oauth_cache")


class UserInfoBase(BaseModel):
    at_hash: str
    aud: str
    auth_time: int
    c_hash: str
    exp: int
    iat: int
    iss: str
    nbf: int
    sid: str
    sub: str
    model_config = ConfigDict(extra="allow", populate_by_name=True)


class FrejaEIDDocumentUserInfo(UserInfoBase):
    personal_identity_number: str = Field(alias="https://frejaeid.com/oidc/claims/personalIdentityNumber")
    document: Any = Field(alias="https://frejaeid.com/oidc/claims/document")
    registration_level: FrejaRegistrationLevel = Field(alias="https://frejaeid.com/oidc/claims/registrationLevel")
    country: str = Field(alias="https://frejaeid.com/oidc/claims/country")
    family_name: str
    given_name: str
    name: Optional[str] = None
    user_id: str = Field(alias="https://frejaeid.com/oidc/claims/relyingPartyUserId")
    transaction_id: str

    @field_validator("country")
    @classmethod
    def country_name_to_alpha2(cls, v):
        # translate ISO 3166-1 alpha-3 to alpha-2 to match the format used in eduid-userdb
        try:
            country = countries.get(v)
        except KeyError:
            raise ValueError(f"country code {v} not found in iso3166")
        return country.alpha2


class FrejaEIDTokenResponse(BaseModel):
    access_token: str
    expires_at: int
    expires_in: int
    id_token: str
    token_type: str
    userinfo: FrejaEIDDocumentUserInfo
