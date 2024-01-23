from typing import cast

from eduid.vccs.client import VCCSClient

TESTING = False
_test_client = None


def get_vccs_client(vccs_url: str) -> VCCSClient:
    """
    Instantiate a VCCS client.
    :param vccs_url: VCCS authentication backend URL
    :return: vccs client
    """
    if TESTING and vccs_url == "dummy":
        global _test_client
        if not _test_client:
            # Avoid circular imports
            from eduid.webapp.common.authn.testing import MockVCCSClient

            _test_client = MockVCCSClient()
        return cast(VCCSClient, _test_client)
    return VCCSClient(
        base_url=vccs_url,
    )
