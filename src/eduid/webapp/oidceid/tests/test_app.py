from typing import Any

import pytest

from eduid.common.clients.oidc_client.base import OidcRpClient
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.oidceid.app import OidcEidApp, init_oidceid_app

OP = "https://op.example.com/oidc"


class OidcEidAppTests(EduidAPITestCase[OidcEidApp]):
    @classmethod
    def load_app(cls, config: dict[str, Any]) -> OidcEidApp:
        return init_oidceid_app("testing", config)

    @pytest.fixture(scope="class")
    @classmethod
    def update_config(cls) -> dict[str, Any]:
        config = cls._get_base_config()
        # pygrindvakt only accepts https redirect URIs for non-loopback hosts
        config["preferred_url_scheme"] = "https"
        config.update(
            {
                "providers": [
                    {
                        "client_id": "test_client_id",
                        "client_secret": "test_client_secret",
                        "token_endpoint_auth_method": "client_secret_basic",
                        "issuer": OP,
                    }
                ],
                "freja_idp": OP,
                "foreign_identity_idp": OP,
            }
        )
        return config

    def test_app_starts(self) -> None:
        assert isinstance(self.app, OidcEidApp)
        # discovery is lazy, creating the client does no network access
        assert list(self.app.oidc_clients) == [OP]
        client: OidcRpClient = self.app.oidc_clients[OP]
        assert client is not None
        assert "oidceid" in self.app.blueprints
