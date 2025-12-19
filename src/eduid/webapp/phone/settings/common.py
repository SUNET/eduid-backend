from datetime import timedelta

from eduid.common.config.base import (
    AmConfigMixin,
    CaptchaConfigMixin,
    EduIDBaseAppConfig,
    MagicCookieMixin,
    MsgConfigMixin,
)


class PhoneConfig(EduIDBaseAppConfig, MagicCookieMixin, AmConfigMixin, MsgConfigMixin, CaptchaConfigMixin):
    """
    Configuration for the phone app
    """

    app_name: str = "phone"

    # timeout for phone verification token, in seconds
    phone_verification_timeout: int = 7200
    throttle_resend_seconds: int = 300
    # default country code
    default_country_code: str = "46"
    state_db_auto_expire: timedelta | None = timedelta(days=7)
