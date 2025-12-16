import logging
from datetime import date
from enum import Enum, unique

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

    authn_request_failed = "freja_eid.authn_request_failed"
    authorization_error = "freja_eid.authorization_fail"
    credential_not_found = "freja_eid.credential_not_found"
    credential_verification_not_allowed = "freja_eid.credential_verification_not_allowed"
    credential_verify_success = "freja_eid.credential_verify_success"
    frontend_action_not_supported = "freja_eid.frontend_action_not_supported"
    identity_not_matching = "freja_eid.identity_not_matching"
    identity_verify_success = "freja_eid.identity_verify_success"
    method_not_available = "freja_eid.method_not_available"
    mfa_authn_success = "freja_eid.mfa_authn_success"
    mfa_authn_not_allowed = "freja_eid.mfa_authn_not_allowed"
    registration_level_not_satisfied = "freja_eid.registration_level_not_satisfied"


class SessionOAuthCache:
    # Used to store json-encoded data (OAuth->BaseOAuth->FrameworkIntegration)
    @staticmethod
    def get(key: str) -> str | None:
        logger.debug(f"Getting {key} from session.freja_eid.oauth_cache")
        return session.freja_eid.rp.authlib_cache.get(key)

    @staticmethod
    def set(key: str, value: str, expires: int | None = None) -> None:
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
        alias="https://frejaeid.com/oidc/claims/personalIdentityNumber", default=None
    )
    date_of_birth: date = Field(alias="birthdate")
    registration_level: FrejaRegistrationLevel = Field(alias="https://frejaeid.com/oidc/claims/registrationLevel")
    loa_level: str = Field(alias="https://frejaeid.com/oidc/claims/loaLevel")
    user_id: str = Field(alias="https://frejaeid.com/oidc/claims/relyingPartyUserId")
    transaction_id: str = Field(alias="https://frejaeid.com/oidc/claims/transactionReference")


class FrejaEIDTokenResponse(BaseModel):
    access_token: str
    token_type: str
    id_token: str
    expires_at: int | None = Field(default=None)
    expires_in: int | None = Field(default=None)
    userinfo: FrejaEIDDocumentUserInfo
