from datetime import timedelta

from pydantic import Field

from eduid.common.config.base import AmConfigMixin, EduIDBaseAppConfig, ErrorsConfigMixin


class OrcidConfig(EduIDBaseAppConfig, AmConfigMixin, ErrorsConfigMixin):
    """
    Configuration for the orcid app
    """

    app_name: str = "orcid"

    # OIDC
    client_registration_info: dict[str, str] = Field(default={"client_id": "", "client_secret": ""})
    provider_configuration_info: dict[str, str] = Field(
        default={
            "issuer": "",
        }
    )
    userinfo_endpoint_method: str = "GET"
    orcid_verify_redirect_url: str = "/profile/accountlinking"
    state_db_auto_expire: timedelta | None = timedelta(days=7)
