import logging
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any

from oic.exception import CommunicationError
from oic.oic import Client
from oic.oic.message import RegistrationRequest
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from requests.exceptions import ConnectionError

__author__ = "lundberg"

logger = logging.getLogger(__name__)


class OidcServiceUnavailableError(Exception):
    """Exception raised when OIDC service is temporarily unavailable"""


class LazyOidcClient:
    """
    A wrapper around the OIDC Client that implements lazy initialization
    and circuit breaker pattern for resilience against external service failures.
    """

    def __init__(
        self,
        client_registration_info: Mapping[str, Any],
        provider_configuration_info: Mapping[str, Any],
        max_failures: int = 3,
        retry_delay_minutes: int = 5,
    ) -> None:
        self.client_registration_info = client_registration_info
        self.provider_configuration_info = provider_configuration_info
        self.max_failures = max_failures
        self.retry_delay = timedelta(minutes=retry_delay_minutes)

        # Internal state
        self._client: Client | None = None
        self._failure_count: int = 0
        self._last_failure_time: datetime | None = None
        self._client_init_failed = False

        logger.info("LazyOidcClient initialized with circuit breaker pattern")

    @property
    def client(self) -> Client:
        """Get the OIDC client, initializing it lazily with circuit breaker protection"""
        if self._client is not None:
            return self._client

        # Circuit breaker logic
        if self._should_skip_initialization():
            raise OidcServiceUnavailableError(
                "OIDC service initialization skipped temporarily due to repeated failures"
            )

        try:
            self._client = self._create_client()
            self._reset_failure_state()
            logger.info("OIDC client initialized successfully")
            return self._client

        except (CommunicationError, ConnectionError) as e:
            self._handle_initialization_failure(e)
            raise OidcServiceUnavailableError(f"OIDC service unavailable: {str(e)}") from e

    def _create_client(self) -> Client:
        """Create and configure the OIDC client"""
        oidc_client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
        oidc_client.store_registration_info(RegistrationRequest(**self.client_registration_info))
        provider = self.provider_configuration_info["issuer"]
        oidc_client.provider_config(provider)
        return oidc_client

    def _should_skip_initialization(self) -> bool:
        """Circuit breaker logic to determine if initialization should be skipped"""
        if not self._client_init_failed:
            return False

        if self._failure_count < self.max_failures:
            return False

        if self._last_failure_time is None:
            return False

        # Allow retry after delay
        return datetime.now() - self._last_failure_time < self.retry_delay

    def _handle_initialization_failure(self, error: Exception) -> None:
        """Track failures for circuit breaker pattern"""
        self._client_init_failed = True
        self._failure_count += 1
        self._last_failure_time = datetime.now()

        logger.warning(f"OIDC client initialization failed (attempt {self._failure_count}): {error}")

        if self._failure_count >= self.max_failures:
            logger.error(
                f"OIDC service marked as unavailable after {self.max_failures} failures. "
                f"It will be possible to try again after {self.retry_delay}."
            )

    def _reset_failure_state(self) -> None:
        """Reset failure tracking on successful initialization"""
        self._client_init_failed = False
        self._failure_count = 0
        self._last_failure_time = None

    # Proxy methods to make LazyOidcClient behave like a Client
    def __getattr__(self, name: str) -> object:
        """Proxy attribute access to the underlying client"""
        return getattr(self.client, name)


def init_lazy_client(
    client_registration_info: Mapping[str, Any],
    provider_configuration_info: Mapping[str, Any],
    max_failures: int = 3,
    retry_delay_minutes: int = 5,
) -> LazyOidcClient:
    """
    Create a lazy-loading OIDC client with circuit breaker pattern.

    Args:
        client_registration_info: Client registration information
        provider_configuration_info: Provider configuration information
        max_failures: Maximum number of failures before circuit breaker opens
        retry_delay_minutes: Minutes to wait before retrying after circuit breaker opens

    Returns:
        LazyOidcClient instance that will initialize the client only when needed
    """
    return LazyOidcClient(
        client_registration_info=client_registration_info,
        provider_configuration_info=provider_configuration_info,
        max_failures=max_failures,
        retry_delay_minutes=retry_delay_minutes,
    )
