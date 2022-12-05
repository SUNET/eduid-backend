import unittest
from typing import List
import fnmatch

from pydantic import BaseModel

from eduid.workers.amapi.config import EndpointRestriction, SupportedMethod
from eduid.workers.amapi.middleware import AuthenticationMiddleware


class TestStructureMiddleware(BaseModel):
    name: str
    glob_endpoints: List[EndpointRestriction]
    path: str
    want: bool


class TestMiddleware(unittest.TestCase):
    def setUp(self, *args, **kwargs):
        super().setUp()
        self.middleware = AuthenticationMiddleware


class TestGlobMatch(TestMiddleware):
    def setUp(self, *args, **kwargs):
        super().setUp()

        self.tts = [
            TestStructureMiddleware(
                name="OK",
                glob_endpoints=[
                    EndpointRestriction(
                        endpoint="/users/*/email",
                        method=SupportedMethod.DELETE,
                    ),
                    EndpointRestriction(
                        endpoint="/users/*/name",
                        method=SupportedMethod.GET,
                    ),
                ],
                path="get:/users/hubba-bubba/name",
                want=True,
            ),
            TestStructureMiddleware(
                name="Not_OK",
                glob_endpoints=[
                    EndpointRestriction(
                        endpoint="/users/*/email",
                        method=SupportedMethod.DELETE,
                    ),
                    EndpointRestriction(
                        endpoint="/users/*/name",
                        method=SupportedMethod.GET,
                    ),
                ],
                path="delete:/users/hubba-bubba/name",
                want=False,
            ),
        ]

    def test(self):
        for tt in self.tts:
            with self.subTest(name=tt.name):
                assert self.middleware.glob_match(endpoints=tt.glob_endpoints, method_path=tt.path) is tt.want

