from typing import Optional

from pydantic import Field

from eduid.common.config.base import EduidEnvironment, PasswordConfigMixin
from eduid.common.models.generic import AnyUrlStr, HttpUrlStr


class JsAppsConfig(PasswordConfigMixin):
    """
    Dashboard, Signup and Login front-end configuration.

    This is sent to the client, so care must be taken to avoid setting secrets here.
    """

    available_languages: dict[str, str] = Field(default={"en": "English", "sv": "Svenska"})
    csrf_token: Optional[str] = None
    dashboard_link: HttpUrlStr
    debug: bool = False
    eduid_site_link: HttpUrlStr = Field(default=HttpUrlStr("https://eduid.se"))
    eduid_site_name: str = "eduID"
    environment: EduidEnvironment = EduidEnvironment.production
    faq_link: HttpUrlStr
    # reset_password_link is used for directing a user to the reset password app
    reset_password_link: HttpUrlStr
    sentry_dsn: Optional[str] = None
    signup_link: HttpUrlStr
    # backend endpoint urls
    authn_service_url: HttpUrlStr
    bankid_service_url: HttpUrlStr
    eidas_service_url: HttpUrlStr
    emails_service_url: HttpUrlStr
    # error_info_url needs to be a full URL since the backend is on the idp, not on https://eduid.se
    error_info_url: Optional[HttpUrlStr] = None
    group_mgmt_service_url: HttpUrlStr
    ladok_service_url: HttpUrlStr
    letter_proofing_service_url: HttpUrlStr
    # login_next_url needs to be a full URL since the backend is on the idp, not on https://eduid.se
    login_next_url: HttpUrlStr
    # login_request_other_url needs to be a full URL since the backend is on the idp, not on https://eduid.se
    login_request_other_url: Optional[HttpUrlStr] = None
    login_service_url: HttpUrlStr
    lookup_mobile_proofing_service_url: HttpUrlStr
    orcid_service_url: HttpUrlStr
    personal_data_service_url: HttpUrlStr
    phone_service_url: HttpUrlStr
    reset_password_service_url: HttpUrlStr
    security_service_url: HttpUrlStr
    signup_service_url: HttpUrlStr
    svipe_service_url: Optional[HttpUrlStr] = None  # if not set the frontend component will not show
    # Dashboard config
    default_country_code: int = 46
    token_verify_idp: HttpUrlStr
    # Signup config
    tous: Optional[dict[str, str]] = None
