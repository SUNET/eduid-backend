"""
Configuration (file) handling for the eduID email app.
"""

from datetime import timedelta

from eduid.common.config.base import (
    AmConfigMixin,
    EduIDBaseAppConfig,
    ErrorsConfigMixin,
    MagicCookieMixin,
)


class EmailConfig(EduIDBaseAppConfig, MagicCookieMixin, AmConfigMixin, ErrorsConfigMixin):
    """
    Configuration for the email app
    """

    app_name: str = "email"

    eduid_site_name: str = "eduID"
    email_verification_timeout: timedelta = timedelta(days=1)
    throttle_resend_seconds: int = 300
    state_db_auto_expire: timedelta | None = timedelta(days=7)
