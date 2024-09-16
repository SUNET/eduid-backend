#
from datetime import timedelta

from pydantic import Field

from eduid.common.clients.gnap_client.base import GNAPClientAuthData
from eduid.common.config.base import (
    AmConfigMixin,
    CaptchaConfigMixin,
    EduIDBaseAppConfig,
    MagicCookieMixin,
    MailConfigMixin,
    PasswordConfigMixin,
    TouConfigMixin,
)
from eduid.common.models.generic import AnyUrlStr


class SignupConfig(
    EduIDBaseAppConfig,
    MagicCookieMixin,
    AmConfigMixin,
    MailConfigMixin,
    TouConfigMixin,
    CaptchaConfigMixin,
    PasswordConfigMixin,
):
    """
    Configuration for the signup app
    """

    app_name: str = "signup"

    vccs_url: str
    signup_url: str
    dashboard_url: str

    password_length: int = 12
    throttle_resend: timedelta = Field(default=timedelta(minutes=5))
    email_verification_code_length: int = 6
    email_verification_max_bad_attempts: int = 3
    email_verification_timeout: timedelta = Field(default=timedelta(minutes=10))
    email_proofing_version: str = Field(default="2013v1")
    default_finish_url: str = "https://www.eduid.se/"
    eduid_site_url: str = "https://www.eduid.se"  # TODO: Backwards compatibility, remove when no longer used
    eduid_site_name: str = "eduID"
    scim_api_url: AnyUrlStr | None = None
    gnap_auth_data: GNAPClientAuthData | None = None
    eduid_scope: str = "eduid.se"
    private_userdb_auto_expire: timedelta | None = Field(default=timedelta(days=7))
