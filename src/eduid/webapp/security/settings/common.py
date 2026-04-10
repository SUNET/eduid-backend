from datetime import timedelta

from pydantic import Field

from eduid.common.config.base import (
    AmConfigMixin,
    EduIDBaseAppConfig,
    Fido2RpConfigMixin,
    FrontendActionMixin,
    MagicCookieMixin,
    MsgConfigMixin,
    PasswordConfigMixin,
    VCCSConfigMixin,
    WebauthnRegistrationConfigMixin,
)


class SecurityConfig(
    EduIDBaseAppConfig,
    Fido2RpConfigMixin,
    WebauthnRegistrationConfigMixin,
    MagicCookieMixin,
    AmConfigMixin,
    MsgConfigMixin,
    PasswordConfigMixin,
    FrontendActionMixin,
    VCCSConfigMixin,
):
    """
    Configuration for the security app
    """

    app_name: str = "security"

    dashboard_url: str
    throttle_update_user_period: timedelta = Field(default=timedelta(seconds=600))

    # change password
    chpass_reauthn_timeout: timedelta = Field(default=timedelta(seconds=120))
    chpass_old_password_needed: bool = True

    # webauthn (security-specific settings; common ones inherited from WebauthnRegistrationConfigMixin)
    webauthn_recommended_user_verification_methods: list[str] = Field(
        default=[
            "faceprint_internal",
            "passcode_external",
            "passcode_internal",
            "handprint_internal",
            "pattern_internal",
            "voiceprint_internal",
            "fingerprint_internal",
            "eyeprint_internal",
            "apple",
        ]
    )
    webauthn_recommended_key_protection: list[str] = Field(
        default=["remote_handle", "hardware", "secure_element", "tee", "apple"]
    )

    # for logging out when terminating an account
    logout_endpoint: str = "https://dashboard.eduid.se/services/authn/logout"
    # URL to send the user to after terminating the account
    termination_redirect_url: str = "https://eduid.se"
