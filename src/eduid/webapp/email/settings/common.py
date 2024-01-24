"""
Configuration (file) handling for the eduID email app.
"""


from eduid.common.config.base import (
    AmConfigMixin,
    EduIDBaseAppConfig,
    ErrorsConfigMixin,
    MagicCookieMixin,
    MailConfigMixin,
)


class EmailConfig(EduIDBaseAppConfig, MagicCookieMixin, AmConfigMixin, MailConfigMixin, ErrorsConfigMixin):
    """
    Configuration for the email app
    """

    app_name: str = "email"

    email_verification_timeout: int = 86400  # seconds
    throttle_resend_seconds: int = 300
    email_verify_redirect_url: str = "/profile/emails"
