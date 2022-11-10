import unittest
from typing import List

from pydantic import BaseModel

from eduid.workers.amapi.middleware import AuthenticationMiddleware


class TestStructureMiddleware(BaseModel):
    name: str
    glob_endpoints: List[str]
    path: str
    want: bool


class TestMiddleware(unittest.TestCase, AuthenticationMiddleware):
    def setUp(self, *args, **kwargs):
        super().setUp()


class TestGlobMatch(TestMiddleware):
    def setUp(self, *args, **kwargs):
        super().setUp()

        self.tts = [
            TestStructureMiddleware(
                name="OK",
                glob_endpoints=[
                    "delete:users/*/email",
                    "get:users/*/name",
                ],
                path="get:users/hubba-bubba/name",
                want=True,
            ),
            TestStructureMiddleware(
                name="Not_OK",
                glob_endpoints=[
                    "delete:users/*/email",
                    "get:users/*/name",
                ],
                path="delete:users/hubba-bubba/name",
                want=False,
            ),
        ]

    def test(self):
        for tt in self.tts:
            with self.subTest(name=tt.name):
                assert self.glob_match(endpoints=tt.glob_endpoints, path=tt.path) is tt.want
