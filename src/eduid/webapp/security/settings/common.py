from datetime import timedelta

from fido2.webauthn import AttestationConveyancePreference, UserVerificationRequirement
from fido_mds.models.fido_mds import AuthenticatorStatus
from pydantic import Field

from eduid.common.config.base import (
    AmConfigMixin,
    EduIDBaseAppConfig,
    FrontendActionMixin,
    MagicCookieMixin,
    MailConfigMixin,
    MsgConfigMixin,
    PasswordConfigMixin,
    WebauthnConfigMixin2,
)


class SecurityConfig(
    EduIDBaseAppConfig,
    WebauthnConfigMixin2,
    MagicCookieMixin,
    AmConfigMixin,
    MsgConfigMixin,
    MailConfigMixin,
    PasswordConfigMixin,
    FrontendActionMixin,
):
    """
    Configuration for the security app
    """

    app_name: str = "security"

    vccs_url: str
    dashboard_url: str
    throttle_update_user_period: timedelta = Field(default=timedelta(seconds=600))

    # change password
    chpass_reauthn_timeout: timedelta = Field(default=timedelta(seconds=120))
    chpass_old_password_needed: bool = True

    # webauthn
    webauthn_proofing_method: str = Field(default="webauthn metadata")
    webauthn_proofing_version: str = Field(default="2022v1")
    webauthn_max_allowed_tokens: int = 10
    webauthn_attestation: AttestationConveyancePreference | None = None
    webauthn_user_verification: UserVerificationRequirement = UserVerificationRequirement.PREFERRED
    webauthn_allowed_user_verification_methods: list[str] = Field(
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
    webauthn_allowed_key_protection: list[str] = Field(
        default=["remote_handle", "hardware", "secure_element", "tee", "apple"]
    )
    webauthn_allowed_status: list[AuthenticatorStatus] = Field(
        default=[
            AuthenticatorStatus.FIDO_CERTIFIED,
            AuthenticatorStatus.FIDO_CERTIFIED_L1,
            AuthenticatorStatus.FIDO_CERTIFIED_L2,
            AuthenticatorStatus.FIDO_CERTIFIED_L3,
            AuthenticatorStatus.FIDO_CERTIFIED_L1plus,
            AuthenticatorStatus.FIDO_CERTIFIED_L2plus,
            AuthenticatorStatus.FIDO_CERTIFIED_L3plus,
        ]
    )

    # for logging out when terminating an account
    logout_endpoint: str = "https://dashboard.eduid.se/services/authn/logout"
    # URL to send the user to after terminating the account
    termination_redirect_url: str = "https://eduid.se"
