from eduid.common.clients.oidc_client.base import OidcRpClientConfig
from eduid.common.config.base import AmConfigMixin, EduIDBaseAppConfig, ErrorsConfigMixin, FrontendActionMixin

__author__ = "lundberg"


class OrcidClientConfig(OidcRpClientConfig):
    # ORCID's discovery document does not advertise authorization_response_iss_parameter_supported,
    # so a missing iss in the authorization response is tolerated (require_iss stays False)
    require_iss: bool = False
    # ORCID's discovery document does not advertise PKCE support
    code_challenge_method: str | None = None


class OrcidConfig(EduIDBaseAppConfig, AmConfigMixin, ErrorsConfigMixin, FrontendActionMixin):
    app_name: str = "orcid"

    # OIDC
    orcid_client: OrcidClientConfig
