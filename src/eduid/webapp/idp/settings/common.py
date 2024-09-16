"""
Configuration (file) handling for the eduID idp app.
"""

from datetime import timedelta

from pydantic import Field, HttpUrl, field_validator
from pydantic_core.core_schema import ValidationInfo

from eduid.common.config.base import (
    AmConfigMixin,
    CookieConfig,
    EduIDBaseAppConfig,
    TouConfigMixin,
    WebauthnConfigMixin2,
)
from eduid.common.models.generic import HttpUrlStr
from eduid.userdb.identity import IdentityProofingMethod
from eduid.webapp.idp.assurance_data import SwamidAssurance


class IdPConfig(EduIDBaseAppConfig, TouConfigMixin, WebauthnConfigMixin2, AmConfigMixin):
    """
    Configuration for the idp app
    """

    app_name: str = "idp"
    # pysaml2 configuration file. Separate config file with SAML related parameters.
    pysaml2_config: str = "eduid.webapp.common.authn.idp_conf"
    # SAML F-TICKS user anonymization key. If this is set, the IdP will log F-TICKS data
    # on every login.
    fticks_secret_key: str | None = None
    # Get SAML F-TICKS format string.
    fticks_format_string: str = "F-TICKS/SWAMID/2.0#TS={ts}#RP={rp}#AP={ap}#PN={pn}#AM={am}#"
    # URL to static resources that can be used in templates
    static_link: str = "#"
    # Lifetime of SSO sessions
    sso_session_lifetime: timedelta = Field(default=timedelta(minutes=600))
    # Verify request signatures, if they exist.
    # This defaults to False since it is a trivial DoS to consume all the IdP:s
    # CPU resources if this is set to True.
    verify_request_signatures: bool = False
    # Get list of usernames valid for use with the /status URL.
    # If this list is ['*'], all usernames are allowed for /status.
    status_test_usernames: list[str] = Field(default=[])
    # URL (string) for use in simple templating of login.html.
    signup_link: str = "#"
    # URL (string) for use in simple templating of forbidden.html.
    dashboard_link: str = "#"
    # URL (string) for use in simple templating of login.html.
    password_reset_link: str = "#"
    # More links
    technicians_link: str = "#"
    student_link: str = "#"
    staff_link: str = "#"
    faq_link: str = "#"
    # Default language code to use when looking for web pages ('en').
    default_language: str = "en"
    # The scope to append to any unscoped eduPersonPrincipalName
    # attributes found on users in the userdb.
    default_eppn_scope: str = "eduid.se"
    # Default country code to use in attribute release as c - ISO_COUNTRY_CODE
    default_country_code: str = "se"
    # Default country to use in attribute release as co - ISO_COUNTRY_NAME
    default_country: str = "Sweden"
    # Disallow login for a user after N failures in a given month.
    # This is said to be an imminent Kantara requirement.
    # Kantara 30-day bad authn limit is 100
    max_auhtn_failures_per_month: int = 50
    max_authn_failures_per_month: int = 50
    # URL to use with VCCS client. BCP is to have an nginx or similar on
    # localhost that will proxy requests to a currently available backend
    # using TLS.
    vccs_url: str = "http://localhost:8550/"
    # The interval which a user needs to re-accept an already accepted ToU (in seconds)
    tou_reaccept_interval: timedelta = Field(default=timedelta(days=3 * 365))
    # Legacy parameters for the SSO cookie. Keep in sync with sso_cookie above until removed!
    sso_cookie_name: str = "idpauthn"
    sso_cookie_domain: str | None = None
    # Cookie for IdP-specific session allowing users to SSO.
    # Must be specified after sso_cookie_name and sso_cookie_domain while those are present.
    sso_cookie: CookieConfig = Field(default_factory=lambda: CookieConfig(key="idpauthn"))
    # List in order of preference
    supported_digest_algorithms: list[str] = Field(default=["http://www.w3.org/2001/04/xmlenc#sha256"])
    # List in order of preference
    supported_signing_algorithms: list[str] = Field(default=["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"])
    eduperson_targeted_id_secret_key: str = ""
    pairwise_id_secret_key: str = ""
    eduid_site_url: str
    login_bundle_url: HttpUrlStr | None = None
    other_device_url: HttpUrlStr | None = None
    esi_ladok_prefix: str = Field(default="urn:schac:personalUniqueCode:int:esi:ladok.se:externtstudentuid-")
    allow_other_device_logins: bool = False
    other_device_logins_ttl: timedelta = Field(default=timedelta(minutes=2))
    other_device_max_code_attempts: int = 3
    other_device_secret_key: str  # secretbox key for protecting the login-with-other-device shared ID
    # SPs that are allowed to request a login for a particular user (idpproxy for stepup, dashboard for chpass, ...)
    request_subject_allowed_entity_ids: list[str] = Field(default=[])
    known_devices_secret_key: str  # secretbox key for decrypting the data stored in the browser local storage
    known_devices_new_ttl: timedelta = Field(default=timedelta(minutes=30))
    known_devices_ttl: timedelta = Field(default=timedelta(days=90))
    known_devices_feature_enabled: bool = False
    # secret key for encrypting personal information for geo-location service
    geo_statistics_secret_key: str | None = None
    geo_statistics_feature_enabled: bool = False
    geo_statistics_url: HttpUrlStr | None = None
    swamid_assurance_profile_1: list[SwamidAssurance] = Field(
        default=[
            SwamidAssurance.SWAMID_AL1,
            SwamidAssurance.REFEDS_ASSURANCE,
            SwamidAssurance.REFEDS_ID_UNIQUE,
            SwamidAssurance.REFEDS_EPPN_UNIQUE,
            SwamidAssurance.REFEDS_IAP_LOW,
        ]
    )
    swamid_assurance_profile_2: list[SwamidAssurance] = Field(
        default=[
            SwamidAssurance.SWAMID_AL1,
            SwamidAssurance.SWAMID_AL2,
            SwamidAssurance.REFEDS_ASSURANCE,
            SwamidAssurance.REFEDS_PROFILE_CAPPUCCINO,
            SwamidAssurance.REFEDS_ID_UNIQUE,
            SwamidAssurance.REFEDS_EPPN_UNIQUE,
            SwamidAssurance.REFEDS_IAP_LOW,
            SwamidAssurance.REFEDS_IAP_MEDIUM,
        ]
    )
    swamid_assurance_profile_3: list[SwamidAssurance] = Field(
        default=[
            SwamidAssurance.SWAMID_AL1,
            SwamidAssurance.SWAMID_AL2,
            SwamidAssurance.SWAMID_AL3,
            SwamidAssurance.REFEDS_ASSURANCE,
            SwamidAssurance.REFEDS_PROFILE_CAPPUCCINO,
            SwamidAssurance.REFEDS_PROFILE_ESPRESSO,
            SwamidAssurance.REFEDS_ID_UNIQUE,
            SwamidAssurance.REFEDS_EPPN_UNIQUE,
            SwamidAssurance.REFEDS_IAP_LOW,
            SwamidAssurance.REFEDS_IAP_MEDIUM,
            SwamidAssurance.REFEDS_IAP_HIGH,
        ]
    )
    logout_finish_url: dict[str, HttpUrl] = Field(
        default={
            "https://dashboard.eduid.docker/services/authn/saml2-metadata": "https://dashboard.eduid.docker/profile/",
            "https://dashboard.dev.eduid.se/services/authn/saml2-metadata": "https://dev.eduid.se/",
            "https://dashboard.eduid.se/services/authn/saml2-metadata": "https://eduid.se/",
        }
    )
    digg_loa2_allowed_identity_proofing_methods: list[IdentityProofingMethod] = Field(
        default=[
            IdentityProofingMethod.SWEDEN_CONNECT,
            IdentityProofingMethod.BANKID,
            IdentityProofingMethod.LETTER,
        ]
    )

    @field_validator("sso_cookie")
    @classmethod
    def make_sso_cookie(cls, v, info: ValidationInfo) -> CookieConfig:
        # Convert sso_cookie from dict to the proper dataclass
        if isinstance(v, dict):
            return CookieConfig(**v)
        if "sso_cookie_name" in info.data and "sso_cookie_domain" in info.data:
            # let legacy parameters override as long as they are present
            return CookieConfig(key=info.data["sso_cookie_name"], domain=info.data["sso_cookie_domain"])
        raise ValueError(
            "sso_cookie not present, and no fallback values either (sso_cookie_name and sso_cookie_domain)"
        )

    @field_validator("sso_session_lifetime", mode="before")
    @classmethod
    def validate_sso_session_lifetime(cls, v):
        if isinstance(v, int):
            # legacy format for this was number of minutes
            v = v * 60
        if not (
            isinstance(
                v,
                (
                    int,
                    str,
                    timedelta,
                ),
            )
        ):
            raise ValueError("Invalid sso_session_lifetime (must be int, str or timedelta)")
        return v
