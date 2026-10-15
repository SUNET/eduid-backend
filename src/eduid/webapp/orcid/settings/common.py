from eduid.common.clients.oidc_client.base import OidcRpClientConfig
from eduid.common.config.base import AmConfigMixin, EduIDBaseAppConfig, ErrorsConfigMixin, FrontendActionMixin

__author__ = "lundberg"


class OrcidClientConfig(OidcRpClientConfig):
    # ORCID's discovery document does not advertise PKCE support
    code_challenge_method: str | None = None


class OrcidConfig(EduIDBaseAppConfig, AmConfigMixin, ErrorsConfigMixin, FrontendActionMixin):
    app_name: str = "orcid"

    # OIDC
    orcid_client: OrcidClientConfig
