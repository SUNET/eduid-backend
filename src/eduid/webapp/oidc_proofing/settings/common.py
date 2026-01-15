from datetime import timedelta

from pydantic import Field

from eduid.common.config.base import AmConfigMixin, EduIDBaseAppConfig, MsgConfigMixin


class OIDCProofingConfig(EduIDBaseAppConfig, MsgConfigMixin, AmConfigMixin):
    """
    Configuration for the oidc proofing app
    """

    app_name: str = "oidc_proofing"

    eduid_site_name: str = "eduID"
    eduid_site_url: str

    # OIDC
    client_registration_info: dict[str, str] = Field(
        default={"client_id": "can_not_be_empty_string", "client_secret": ""}
    )
    provider_configuration_info: dict[str, str] = Field(
        default={
            "issuer": "can_not_be_empty_string",
            "authorization_endpoint": "",
            "jwks_uri": "",
            "response_types_supported": "",
            "subject_types_supported": "",
            "id_token_signing_alg_values_supported": "",
        }
    )
    userinfo_endpoint_method: str = "POST"
    # Freja config
    freja_jws_algorithm: str = "HS256"
    freja_jws_key_id: str = ""
    freja_jwk_secret: str = ""  # secret in hex
    freja_iarp: str = ""  # Relying party identity
    freja_expire_time_hours: int = 336  # 2 weeks, needs minimum 5 minutes and maximum 60 days
    freja_response_protocol: str = "1.0"  # Version
    # SE-LEG config
    seleg_expire_time_hours: int = 336  # Needs to be the same as FREJA_EXPIRE_TIME_HOURS as state is shared

    state_db_auto_expire: timedelta | None = timedelta(days=21)  # 3 weeks
