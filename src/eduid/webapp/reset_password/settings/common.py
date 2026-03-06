"""
Configuration (file) handling for the eduID reset_password app.
"""

from datetime import timedelta

from pydantic import Field

from eduid.common.config.base import (
    AmConfigMixin,
    CaptchaConfigMixin,
    EduIDBaseAppConfig,
    MagicCookieMixin,
    MsgConfigMixin,
    PasswordConfigMixin,
    VCCSConfigMixin,
    WebauthnConfigMixin2,
)


class ResetPasswordConfig(
    EduIDBaseAppConfig,
    WebauthnConfigMixin2,
    MagicCookieMixin,
    AmConfigMixin,
    MsgConfigMixin,
    PasswordConfigMixin,
    CaptchaConfigMixin,
    VCCSConfigMixin,
):
    """
    Configuration for the reset_password app
    """

    app_name: str = "reset_password"

    # VCCS URL
    dashboard_url: str

    email_code_timeout: timedelta = Field(default=timedelta(hours=2))
    email_code_length: int = 6
    phone_code_timeout: timedelta = Field(default=timedelta(minutes=10))
    # Number of bytes of salt to generate (recommended min 16).
    password_salt_length: int = 32
    # Length of H1 hash to produce (recommended min 32).
    password_hash_length: int = 32
    # bcrypt pbkdf number of rounds.
    # For number of rounds, it is recommended that a measurement is made to achieve
    # a cost of at least 100 ms on current hardware.
    password_generation_rounds: int = 2**5
    # throttle resend of mail and sms
    throttle_resend: timedelta = Field(default=timedelta(minutes=5))
    password_service_url: str = "/services/reset-password/"
    # Throttle sending SMSs for extra security resetting passwords
    throttle_sms: timedelta = Field(default=timedelta(minutes=5))
    eduid_site_url: str = "https://www.eduid.se"
    eduid_site_name: str = "eduID"
    state_db_auto_expire: timedelta | None = Field(default=timedelta(days=7))
