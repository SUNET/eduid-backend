from typing import Any, cast

from eduid.vccs.client import VCCSClient

TESTING = False


class _VCCSClientCache:
    """Singleton cache for VCCS clients."""

    _instance: Any = None

    @classmethod
    def get_test_client(cls) -> VCCSClient:
        if cls._instance is None:
            # Avoid circular imports
            from eduid.webapp.common.authn.testing import MockVCCSClient

            cls._instance = MockVCCSClient()
        return cast(VCCSClient, cls._instance)


def get_vccs_client(vccs_url: str) -> VCCSClient:
    """
    Instantiate a VCCS client.
    :param vccs_url: VCCS authentication backend URL
    :return: vccs client
    """
    if TESTING and vccs_url == "dummy":
        return _VCCSClientCache.get_test_client()
    return VCCSClient(
        base_url=vccs_url,
    )
