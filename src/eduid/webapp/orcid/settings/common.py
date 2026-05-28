from pydantic import Field

from eduid.common.config.base import AmConfigMixin, EduIDBaseAppConfig, ErrorsConfigMixin, FrontendActionMixin


class OrcidConfig(EduIDBaseAppConfig, AmConfigMixin, ErrorsConfigMixin, FrontendActionMixin):
    app_name: str = "orcid"

    # OIDC
    client_registration_info: dict[str, str] = Field(default={"client_id": "", "client_secret": ""})
    provider_configuration_info: dict[str, str] = Field(
        default={
            "issuer": "",
        }
    )
    userinfo_endpoint_method: str = "GET"
