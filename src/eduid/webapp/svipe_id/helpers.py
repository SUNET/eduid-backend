import logging
from datetime import date
from enum import unique
from typing import Any

from iso3166 import countries
from pydantic import BaseModel, ConfigDict, Field, field_validator

from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.session import session

__author__ = "lundberg"


logger = logging.getLogger(__name__)


@unique
class SvipeIDMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # failed to create authn request
    authn_request_failed = "svipe_id.authn_request_failed"
    # Unavailable vetting method requested
    method_not_available = "svipe_id.method_not_available"
    # Identity verification success
    identity_verify_success = "svipe_id.identity_verify_success"
    # Authorization error at Svipe ID
    authorization_error = "svipe_id.authorization_fail"
    frontend_action_not_supported = "svipe_id.frontend_action_not_supported"


class SessionOAuthCache:
    @staticmethod
    def get(key: str) -> Any:
        logger.debug(f"Getting {key} from session.svipe_id.oauth_cache")
        return session.svipe_id.rp.authlib_cache.get(key)

    @staticmethod
    def set(key: str, value: Any, expires: int | None = None) -> None:
        session.svipe_id.rp.authlib_cache[key] = value
        logger.debug(f"Set {key}={value} (expires={expires}) in session.svipe_id.oauth_cache")

    @staticmethod
    def delete(key: str) -> None:
        del session.svipe_id.rp.authlib_cache[key]
        logger.debug(f"Deleted {key} from session.svipe_id.oauth_cache")


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


class SvipeDocumentUserInfo(UserInfoBase):
    birthdate: date
    document_administrative_number: str | None = Field(alias="com.svipe:document_administrative_number", default=None)
    document_expiry_date: date = Field(alias="com.svipe:document_expiry_date")
    # Issuing Country: SWE
    document_issuing_country: str = Field(alias="com.svipe:document_issuing_country")
    # Nationality: SWE  # noqa: ERA001
    document_nationality: str = Field(alias="com.svipe:document_nationality")
    document_number: str = Field(alias="com.svipe:document_number")
    # Document Type (standardized/english): Passport
    document_type_sdn_en: str = Field(alias="com.svipe:document_type_sdn_en")
    family_name: str
    given_name: str
    name: str | None = None
    svipe_id: str = Field(alias="com.svipe:svipeid")
    transaction_id: str = Field(alias="com.svipe:meta_transaction_id")

    @field_validator("document_nationality")
    @classmethod
    def iso_3166_1_alpha_3_to_alpha2(cls, v):
        # translate ISO 3166-1 alpha-3 to alpha-2 to match the format used in eduid-userdb
        try:
            country = countries.get(v)
        except KeyError:
            raise ValueError(f"country code {v} not found in iso3166")
        return country.alpha2


class SvipeTokenResponse(BaseModel):
    access_token: str
    expires_at: int
    expires_in: int
    id_token: str
    token_type: str
    userinfo: SvipeDocumentUserInfo
