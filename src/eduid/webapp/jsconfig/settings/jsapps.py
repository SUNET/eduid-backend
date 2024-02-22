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
    dashboard_url: Optional[str]  # deprecated
    debug: bool = False
    eduid_site_link: HttpUrlStr = Field(default=HttpUrlStr("https://eduid.se"))
    eduid_site_name: str = "eduID"
    eduid_site_url: Optional[str] = "https://eduid.se"  # deprecated
    environment: EduidEnvironment = EduidEnvironment.production
    faq_link: HttpUrlStr
    reset_password_link: HttpUrlStr  # used for directing a user to the reset password app
    sentry_dsn: Optional[str] = None
    signup_link: HttpUrlStr
    signup_url: Optional[str]  # deprecated
    static_faq_url: Optional[str]  # deprecated
    # backend endpoint urls
    authn_service_url: HttpUrlStr
    authn_url: Optional[str]  # deprecated
    bankid_service_url: HttpUrlStr
    eidas_service_url: HttpUrlStr
    eidas_url: Optional[str]  # deprecated
    emails_service_url: HttpUrlStr
    emails_url: Optional[str]  # deprecated
    error_info_url: Optional[HttpUrlStr] = (
        None  # Needs to be a full URL since the backend is on the idp, not on https://eduid.se
    )
    group_mgmt_service_url: HttpUrlStr
    group_mgmt_url: Optional[str]  # deprecated
    ladok_service_url: HttpUrlStr
    ladok_url: Optional[str]  # deprecated
    letter_proofing_service_url: HttpUrlStr
    letter_proofing_url: Optional[str]  # deprecated
    login_base_url: Optional[AnyUrlStr]  # deprecated
    login_next_url: HttpUrlStr  # Needs to be a full URL since the backend is on the idp, not on https://eduid.se
    login_request_other_url: Optional[HttpUrlStr] = (
        None  # Needs to be a full URL since the backend is on the idp, not on https://eduid.se
    )
    login_service_url: HttpUrlStr
    lookup_mobile_proofing_service_url: HttpUrlStr
    lookup_mobile_proofing_url: Optional[str]  # deprecated
    orcid_service_url: HttpUrlStr
    orcid_url: Optional[str]  # deprecated
    personal_data_service_url: HttpUrlStr
    personal_data_url: Optional[str]  # deprecated
    phone_service_url: HttpUrlStr
    phone_url: Optional[str]  # deprecated
    reset_password_service_url: HttpUrlStr
    reset_password_url: Optional[str]  # deprecated
    security_service_url: HttpUrlStr
    security_url: Optional[str]  # deprecated
    svipe_service_url: Optional[HttpUrlStr]  # if not set the frontend component will not show
    svipe_url: Optional[str]  # deprecated
    # Dashboard config
    default_country_code: int = 46
    proofing_methods: list = Field(default=["letter", "lookup_mobile", "oidc", "eidas"])
    token_verify_idp: HttpUrlStr
    # Signup config
    recaptcha_public_key: Optional[str] = None
    tous: Optional[dict[str, str]] = None
