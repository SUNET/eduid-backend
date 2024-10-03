import fnmatch
import unittest

from eduid.workers.amapi.config import EndpointRestriction, SupportedMethod
from eduid.workers.amapi.middleware import AuthenticationMiddleware


class TestMiddleware(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.middleware = AuthenticationMiddleware

    def test_glob_match_true(self) -> None:
        glob_endpoints = [
            EndpointRestriction(
                endpoint="/users/*/email",
                method=SupportedMethod.DELETE,
            ),
            EndpointRestriction(
                endpoint="/users/*/name",
                method=SupportedMethod.GET,
            ),
        ]

        path = "get:/users/hubba-bubba/name"
        assert fnmatch.fnmatch(path, glob_endpoints[1].uri) is True
        assert self.middleware.glob_match(endpoints=glob_endpoints, method_path=path) is True

    def test_glob_long_url(self) -> None:
        glob_endpoints = [
            EndpointRestriction(
                endpoint="/users/*/meta/cleaned",
                method="put",
            ),
        ]
        path = "put:/users/hubba-bubba/meta/cleaned"
        assert fnmatch.fnmatch(path, glob_endpoints[0].uri) is True
        assert self.middleware.glob_match(endpoints=glob_endpoints, method_path=path) is True

    def test_glob_match_false(self) -> None:
        glob_endpoints = [
            EndpointRestriction(
                endpoint="/users/*/email",
                method=SupportedMethod.DELETE,
            ),
            EndpointRestriction(
                endpoint="/users/*/name",
                method=SupportedMethod.GET,
            ),
        ]
        path = "delete:/users/hubba-bubba/name"
        assert fnmatch.fnmatch(path, glob_endpoints[1].uri) is False
        assert self.middleware.glob_match(endpoints=glob_endpoints, method_path=path) is False
