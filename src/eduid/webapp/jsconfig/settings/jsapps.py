from pydantic import Field, HttpUrl

from eduid.common.config.base import EduidEnvironment, PasswordConfigMixin


class JsAppsConfig(PasswordConfigMixin):
    """
    Dashboard, Signup and Login front-end configuration.

    This is sent to the client, so care must be taken to avoid setting secrets here.
    """

    available_languages: dict[str, str] = Field(default={"en": "English", "sv": "Svenska"})
    csrf_token: str | None = None
    dashboard_link: HttpUrl
    debug: bool = False
    eduid_site_link: HttpUrl = Field(default=HttpUrl("https://eduid.se"))
    eduid_site_name: str = "eduID"
    environment: EduidEnvironment = EduidEnvironment.production
    faq_link: HttpUrl
    # reset_password_link is used for directing a user to the reset password app
    reset_password_link: HttpUrl
    sentry_dsn: str | None = None
    signup_link: HttpUrl
    # backend endpoint urls
    authn_service_url: HttpUrl
    bankid_service_url: HttpUrl
    eidas_service_url: HttpUrl
    emails_service_url: HttpUrl
    # error_info_url needs to be a full URL since the backend is on the idp, not on https://eduid.se
    error_info_url: HttpUrl | None = None
    freja_eid_service_url: HttpUrl | None = None
    group_mgmt_service_url: HttpUrl
    ladok_service_url: HttpUrl
    letter_proofing_service_url: HttpUrl
    # login_next_url needs to be a full URL since the backend is on the idp, not on https://eduid.se
    login_next_url: HttpUrl
    # login_request_other_url needs to be a full URL since the backend is on the idp, not on https://eduid.se
    login_request_other_url: HttpUrl | None = None
    login_service_url: HttpUrl
    lookup_mobile_proofing_service_url: HttpUrl
    orcid_service_url: HttpUrl
    personal_data_service_url: HttpUrl
    phone_service_url: HttpUrl
    reset_password_service_url: HttpUrl
    security_service_url: HttpUrl
    signup_service_url: HttpUrl
    svipe_service_url: HttpUrl | None = None  # if not set the frontend component will not show
    # Dashboard config
    default_country_code: int = 46
    token_verify_idp: HttpUrl
    # Signup config
    tous: dict[str, str] | None = None
