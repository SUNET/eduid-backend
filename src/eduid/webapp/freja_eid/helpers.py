import logging
from datetime import date
from enum import Enum, unique
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

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
    # Authorization error at Freja EID
    authorization_error = "freja_eid.authorization_fail"
    frontend_action_not_supported = "freja_eid.frontend_action_not_supported"
    # registration level not satisfied
    registration_level_not_satisfied = "freja_eid.registration_level_not_satisfied"


class SessionOAuthCache:
    @staticmethod
    def get(key: str) -> Any:
        logger.debug(f"Getting {key} from session.freja_eid.oauth_cache")
        return session.freja_eid.rp.authlib_cache.get(key)

    @staticmethod
    def set(key: str, value: Any, expires: int | None = None) -> None:
        session.freja_eid.rp.authlib_cache[key] = value
        logger.debug(f"Set {key}={value} (expires={expires}) in session.freja_eid.oauth_cache")

    @staticmethod
    def delete(key: str) -> None:
        del session.freja_eid.rp.authlib_cache[key]
        logger.debug(f"Deleted {key} from session.freja_eid.oauth_cache")


class UserInfoBase(BaseModel):
    aud: str
    exp: int
    iat: int
    iss: str
    sub: str
    model_config = ConfigDict(extra="allow", populate_by_name=True)


class FrejaDocumentType(Enum):
    PASSPORT = "PASS"
    DRIVING_LICENCE = "DRILIC"
    NATIONAL_ID = "NATID"
    SIS_CERTIFIED_ID = "IDSIS"
    TAX_AGENCY_ID = "TAXID"
    OTHER_ID = "OTHERID"


class FrejaDocument(BaseModel):
    type: FrejaDocumentType
    country: str
    serial_number: str = Field(alias="serialNumber")
    expiration_date: date = Field(alias="expirationDate")
    model_config = ConfigDict(populate_by_name=True)


class FrejaEIDDocumentUserInfo(UserInfoBase):
    country: str = Field(alias="https://frejaeid.com/oidc/claims/country")
    document: FrejaDocument = Field(alias="https://frejaeid.com/oidc/claims/document")
    family_name: str
    given_name: str
    name: str
    personal_identity_number: str | None = Field(
        alias="https:/frejaeid.com/oidc/claims/personalIdentityNumber", default=None
    )
    date_of_birth: date = Field(alias="birthdate")
    registration_level: FrejaRegistrationLevel = Field(alias="https://frejaeid.com/oidc/claims/registrationLevel")
    user_id: str = Field(alias="https://frejaeid.com/oidc/claims/relyingPartyUserId")
    transaction_id: str = Field(alias="https://frejaeid.com/oidc/claims/transactionReference")


class FrejaEIDTokenResponse(BaseModel):
    access_token: str
    expires_at: int
    expires_in: int
    id_token: str
    token_type: str
    userinfo: FrejaEIDDocumentUserInfo
