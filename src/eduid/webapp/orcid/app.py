from collections.abc import Mapping
from typing import Any, cast
from datetime import datetime, timedelta

from flask import current_app
from requests.exceptions import ConnectionError
from oic.exception import CommunicationError

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.userdb.logs import ProofingLog
from eduid.userdb.proofing import OrcidProofingStateDB, OrcidProofingUserDB
from eduid.webapp.common.api import oidc
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.orcid.settings.common import OrcidConfig


__author__ = "lundberg"


class OrcidServiceUnavailableError(Exception):
    """Exception raised when ORCID service is temporarily unavailable"""

    pass


class OrcidApp(AuthnBaseApp):
    def __init__(self, config: OrcidConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        self.conf = config

        # Init dbs
        self.private_userdb = OrcidProofingUserDB(config.mongo_uri)
        self.proofing_statedb = OrcidProofingStateDB(config.mongo_uri)
        self.proofing_log = ProofingLog(config.mongo_uri)

        # Init celery
        self.am_relay = AmRelay(config)

        # Lazy initialization attributes for OIDC client
        self._oidc_client = None
        self._client_init_failed = False
        self._last_failure_time = None
        self._failure_count = 0
        self._max_failures = 3
        self._retry_delay = timedelta(minutes=5)

        self.logger.info("ORCID app initialized with lazy OIDC client loading")

    @property
    def oidc_client(self):
        """Lazy-loaded OIDC client with circuit breaker pattern"""
        if self._oidc_client is not None:
            return self._oidc_client

        # Circuit breaker
        if self._should_skip_initialization():
            raise OrcidServiceUnavailableError(
                "ORCID service initialization skipped temporarily due to repeated failures"
            )

        try:
            self._oidc_client = oidc.init_client(
                self.conf.client_registration_info, self.conf.provider_configuration_info
            )
            self._reset_failure_state()
            self.logger.info("ORCID OIDC client initialized successfully")
            return self._oidc_client

        except (CommunicationError, ConnectionError) as e:
            self._handle_initialization_failure(e)
            raise OrcidServiceUnavailableError(f"ORCID service unavailable: {str(e)}") from e

    def _should_skip_initialization(self) -> bool:
        """Circuit breaker logic"""
        if not self._client_init_failed:
            return False

        if self._failure_count < self._max_failures:
            return False

        # Allow retry after delay
        return datetime.now() - self._last_failure_time < self._retry_delay

    def _handle_initialization_failure(self, error: Exception):
        """Track failures for circuit breaker"""
        self._client_init_failed = True
        self._failure_count += 1
        self._last_failure_time = datetime.now()

        self.logger.warning(f"ORCID OIDC client initialization failed (attempt {self._failure_count}): {error}")

        if self._failure_count >= self._max_failures:
            self.logger.error(
                f"ORCID service marked as unavailable after {self._max_failures} failures. "
                f"It will be possible to try again after {self._retry_delay}."
            )

    def _reset_failure_state(self):
        """Reset failure tracking on successful initialization"""
        self._client_init_failed = False
        self._failure_count = 0
        self._last_failure_time = None


current_orcid_app: OrcidApp = cast(OrcidApp, current_app)


def init_orcid_app(name: str = "orcid", test_config: Mapping[str, Any] | None = None) -> OrcidApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    config = load_config(typ=OrcidConfig, app_name=name, ns="webapp", test_config=test_config)

    app = OrcidApp(config)

    app.logger.info(f"Init {name} app...")

    # Register views
    from eduid.webapp.orcid.views import orcid_views

    app.register_blueprint(orcid_views)

    return app
