# -*- coding: utf-8 -*-

__author__ = "masv"

import json
import datetime
from typing import Any, Dict, Optional

import pkg_resources
from bson import ObjectId
from fastapi.testclient import TestClient
from httpx import Headers
from jwcrypto import jwt
from pydantic import BaseModel

from requests import Response

from fastapi import status

from eduid.common.clients.gnap_client.base import GNAPBearerTokenMixin
from eduid.common.testing_base import CommonTestCase
from eduid.userdb.fixtures.users import new_user_example
from eduid.workers.amapi.app import init_api
from eduid.workers.amapi.config import EndpointRestriction
from eduid.workers.amapi.utils import AuthnBearerToken


class TestAMBase(CommonTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        self.path = pkg_resources.resource_filename(__name__, "data")
        self.test_config = self._get_config()
        self.test_singing_key = "testing-amapi-2106210000"

        self.api = init_api(name="test_api", test_config=self.test_config)
        self.client = TestClient(self.api)

        self.eppn = "hubba-bubba"
        self.source = "mura"
        self.reason = "mura"

    def _get_config(self) -> Dict[str, Any]:
        config = {
            "keystore_path": f"{self.path}/testing_jwks.json",
            "mongo_uri": self.settings["mongo_uri"],
            "user_restriction": {
                "test-service_name": [
                    EndpointRestriction(
                        endpoint="/users/*/name",
                        method="put",
                    ),
                    EndpointRestriction(
                        endpoint="/users/*/phone",
                        method="put",
                    ),
                    EndpointRestriction(
                        endpoint="/users/*/email",
                        method="put",
                    ),
                    EndpointRestriction(
                        endpoint="/users/*/language",
                        method="put",
                    ),
                    EndpointRestriction(
                        endpoint="/users/*/terminate",
                        method="put",
                    ),
                ],
            },
        }
        return config

    @staticmethod
    def as_json(data: dict) -> str:
        return json.dumps(data)


class TestStructureUser(BaseModel):
    name: str
    req: dict
    assert_diff: dict
    oauth_header: Headers
    endpoint: Optional[str] = None
    access_granted: bool
    want_response_status: int

    class Config:
        arbitrary_types_allowed = True


class TestUsers(TestAMBase, GNAPBearerTokenMixin):
    def setUp(self, *args, **kwargs):
        super().setUp(am_users=[new_user_example])

    def _make_url(self, endpoint: Optional[str] = None) -> str:
        if endpoint is None:
            return f"/users/{self.eppn}"
        return f"/users/{self.eppn}/{endpoint}"

    def _audit_log_tests(self, assert_diff: dict):
        audit_logs = self.api.audit_logger.get_by_eppn(self.eppn)
        assert len(audit_logs) == 1
        assert audit_logs[0].eppn == self.eppn
        assert audit_logs[0].reason == self.reason
        assert audit_logs[0].source == self.source
        assert audit_logs[0].diff == self.as_json(assert_diff)

    def make_put_call(self, json_data: dict, oauth_header: Headers, endpoint: Optional[str] = None) -> Response:
        response = self.client.put(
            url=self._make_url(endpoint),
            json=json_data,
            headers=oauth_header,
        )
        return response

    def _auth_header(self, service_name: str) -> Headers:
        expire = datetime.timedelta(seconds=3600)
        signing_key = self.api.jwks.get_key(self.test_singing_key)
        claims = AuthnBearerToken(
            iss="test-issuer",
            sub="test-subject",
            aud="test-Audience",
            exp=expire,
            service_name=service_name,
        )
        token = jwt.JWT(header={"alg": "ES256"}, claims=claims.to_rfc7519())
        token.make_signed_token(signing_key)
        bearer_token = f"Bearer {token.serialize()}"
        return Headers({"Authorization": bearer_token})


class TestUpdateName(TestUsers):
    def setUp(self, *args, **kwargs):
        super().setUp()
        req = {
            "reason": self.reason,
            "source": self.source,
            "given_name": None,
            "display_name": "test_display_name",
            "surname": "Smith",
        }

        self.assert_diff = {
            "dictionary_item_removed": ["root['givenName']"],
            "values_changed": {
                "root['displayName']": {
                    "new_value": "test_display_name",
                    "old_value": "John Smith",
                },
            },
        }

        self.tts = [
            TestStructureUser(
                name="allowed",
                req=req,
                assert_diff=self.assert_diff,
                oauth_header=self._auth_header("test-service_name"),
                endpoint="name",
                access_granted=True,
                want_response_status=status.HTTP_200_OK,
            ),
            TestStructureUser(
                name="not_allowed",
                req=req,
                assert_diff=self.assert_diff,
                oauth_header=self._auth_header(service_name="wrong_service_name"),
                endpoint="name",
                access_granted=False,
                want_response_status=status.HTTP_401_UNAUTHORIZED,
            ),
        ]

    def test(self):
        for tt in self.tts:
            with self.subTest(name=tt.name):
                got = self.make_put_call(
                    json_data=tt.req,
                    oauth_header=tt.oauth_header,
                    endpoint=tt.endpoint,
                )
                assert got.status_code == tt.want_response_status

                if tt.access_granted:
                    user_after = self.amdb.get_user_by_eppn(self.eppn)
                    assert user_after.given_name is None
                    assert user_after.display_name == "test_display_name"
                    assert user_after.surname == "Smith"
                    assert user_after.meta.version is not ObjectId("987654321098765432103210")

                    self._audit_log_tests(assert_diff=self.assert_diff)
                else:
                    pass


class TestUpdateEmail(TestUsers):
    def setUp(self, *args, **kwargs):
        super().setUp()
        req = {
            "reason": self.reason,
            "source": self.source,
            "mail_addresses": [
                {
                    "email": "test@example.com",
                    "created_by": "signup",
                    "created_ts": "2013-09-02T10:23:25+00:00",
                    "is_verified": True,
                    "verified_by": "signup",
                    "verified_ts": "2013-09-02T10:23:25+00:00",
                    "is_primary": True,
                    "modified_ts": "2013-09-02T10:23:25+00:00",
                }
            ],
        }

        self.assert_diff = {
            "values_changed": {
                "root['mailAliases'][0]": {
                    "new_value": {
                        "created_by": "signup",
                        "created_ts": "2013-09-02T10:23:25+00:00",
                        "modified_ts": "2013-09-02T10:23:25+00:00",
                        "verified_by": "signup",
                        "verified_ts": "2013-09-02T10:23:25+00:00",
                        "email": "test@example.com",
                        "primary": True,
                        "verified": True,
                    },
                    "old_value": {
                        "created_by": "signup",
                        "created_ts": "2013-09-02T10:23:25+00:00",
                        "verified_by": "signup",
                        "verified_ts": "2013-09-02T10:23:25+00:00",
                        "email": "johnsmith@example.com",
                        "primary": True,
                        "verified": True,
                    },
                },
            },
            "iterable_item_removed": {
                "root['mailAliases'][1]": {
                    "created_by": "dashboard",
                    "created_ts": "2013-09-02T10:23:25+00:00",
                    "verified_by": "dashboard",
                    "verified_ts": "2013-09-02T10:23:25+00:00",
                    "email": "johnsmith2@example.com",
                    "primary": False,
                    "verified": False,
                },
            },
        }

        self.tts = [
            TestStructureUser(
                name="allowed",
                req=req,
                assert_diff=self.assert_diff,
                oauth_header=self._auth_header(service_name="test-service_name"),
                endpoint="email",
                access_granted=True,
                want_response_status=status.HTTP_200_OK,
            ),
            TestStructureUser(
                name="not_allowed",
                req=req,
                assert_diff=self.assert_diff,
                oauth_header=self._auth_header(service_name="wrong-service_name"),
                endpoint="email",
                access_granted=False,
                want_response_status=status.HTTP_401_UNAUTHORIZED,
            ),
        ]

    def test(self):
        for tt in self.tts:
            with self.subTest(name=tt.name):
                got = self.make_put_call(
                    json_data=tt.req,
                    oauth_header=tt.oauth_header,
                    endpoint=tt.endpoint,
                )
                assert got.status_code == tt.want_response_status

                if tt.access_granted:
                    user_after = self.amdb.get_user_by_eppn(self.eppn)
                    assert user_after.mail_addresses.to_list()[0].email == "test@example.com"
                    assert len(user_after.mail_addresses.to_list()) == 1

                    self._audit_log_tests(assert_diff=self.assert_diff)
                else:
                    pass


class TestUpdateLanguage(TestUsers):
    def setUp(self, *args, **kwargs):
        super().setUp()
        req = {
            "reason": self.reason,
            "source": self.source,
            "language": "test",
        }

        self.assert_diff = {
            "values_changed": {
                "root['preferredLanguage']": {
                    "new_value": "test",
                    "old_value": "en",
                },
            },
        }

        self.tts = [
            TestStructureUser(
                name="allowed",
                req=req,
                assert_diff=self.assert_diff,
                oauth_header=self._auth_header(service_name="test-service_name"),
                endpoint="language",
                access_granted=True,
                want_response_status=status.HTTP_200_OK,
            ),
            TestStructureUser(
                name="not_allowed",
                req=req,
                assert_diff=self.assert_diff,
                oauth_header=self._auth_header(service_name="wrong-service_name"),
                endpoint="language",
                access_granted=False,
                want_response_status=status.HTTP_401_UNAUTHORIZED,
            ),
        ]

    def test(self):
        for tt in self.tts:
            with self.subTest(name=tt.name):
                got = self.make_put_call(
                    json_data=tt.req,
                    oauth_header=tt.oauth_header,
                    endpoint=tt.endpoint,
                )

                assert got.status_code == tt.want_response_status

                if tt.access_granted:
                    user_after = self.amdb.get_user_by_eppn(self.eppn)
                    assert user_after.language == "test"

                    self._audit_log_tests(assert_diff=self.assert_diff)
                else:
                    pass


class TestUpdatePhone(TestUsers):
    def setUp(self, *args, **kwargs):
        super().setUp()

        req = {
            "reason": self.reason,
            "source": self.source,
            "phone_numbers": [
                {
                    "number": "08197806",
                    "created_by": "signup",
                    "created_ts": "2013-09-02T10:23:25",
                    "is_verified": True,
                    "verified_by": "signup",
                    "verified_ts": "2013-09-02T10:23:25",
                    "is_primary": True,
                    "modified_ts": "2013-09-02T10:23:25",
                }
            ],
        }

        self.assert_diff = {
            "values_changed": {
                "root['phone'][0]": {
                    "new_value": {
                        "created_by": "signup",
                        "created_ts": "2013-09-02T10:23:25",
                        "modified_ts": "2013-09-02T10:23:25",
                        "verified_by": "signup",
                        "verified_ts": "2013-09-02T10:23:25",
                        "number": "08197806",
                        "primary": True,
                        "verified": True,
                    },
                    "old_value": {
                        "created_by": "dashboard",
                        "created_ts": "2013-09-02T10:23:25+00:00",
                        "verified_by": "dashboard",
                        "verified_ts": "2013-09-02T10:23:25+00:00",
                        "number": "+34609609609",
                        "primary": True,
                        "verified": True,
                    },
                }
            },
            "iterable_item_removed": {
                "root['phone'][1]": {
                    "created_by": "dashboard",
                    "created_ts": "2013-09-02T10:23:25+00:00",
                    "verified_ts": "2013-09-02T10:23:25+00:00",
                    "number": "+34 6096096096",
                    "primary": False,
                    "verified": False,
                }
            },
        }

        self.tts = [
            TestStructureUser(
                name="allowed",
                req=req,
                assert_diff=self.assert_diff,
                oauth_header=self._auth_header(service_name="test-service_name"),
                endpoint="phone",
                access_granted=True,
                want_response_status=status.HTTP_200_OK,
            ),
            TestStructureUser(
                name="not_allowed",
                req=req,
                assert_diff=self.assert_diff,
                oauth_header=self._auth_header(service_name="wrong-service_name"),
                endpoint="phone",
                access_granted=False,
                want_response_status=status.HTTP_401_UNAUTHORIZED,
            ),
        ]

    def test(self):
        for tt in self.tts:
            with self.subTest(name=tt.name):
                got = self.make_put_call(
                    json_data=tt.req,
                    oauth_header=tt.oauth_header,
                    endpoint=tt.endpoint,
                )

                assert got.status_code == tt.want_response_status

                if tt.access_granted:
                    user_after = self.amdb.get_user_by_eppn(self.eppn)
                    assert user_after.phone_numbers.to_list()[0].number == "08197806"

                    self._audit_log_tests(assert_diff=self.assert_diff)


class TestTerminate(TestUsers):
    def setUp(self, *args, **kwargs):
        super().setUp()

        req = {
            "source": self.source,
            "reason": self.reason,
        }

        self.assert_diff = {
            "dictionary_item_added": ["root['terminated']"],
        }

        self.tts = [
            TestStructureUser(
                name="allowed",
                req=req,
                assert_diff=self.assert_diff,
                oauth_header=self._auth_header(service_name="test-service_name"),
                endpoint="terminate",
                access_granted=True,
                want_response_status=status.HTTP_200_OK,
            ),
            TestStructureUser(
                name="not_allowed",
                req=req,
                assert_diff=self.assert_diff,
                oauth_header=self._auth_header(service_name="wrong-service_name"),
                endpoint="terminate",
                access_granted=False,
                want_response_status=status.HTTP_401_UNAUTHORIZED,
            ),
        ]

    def test(self):
        for tt in self.tts:
            with self.subTest(name=tt.name):
                got = self.make_put_call(
                    json_data=tt.req,
                    oauth_header=tt.oauth_header,
                    endpoint=tt.endpoint,
                )

                assert got.status_code == tt.want_response_status

            if tt.access_granted:
                user_after = self.amdb.get_user_by_eppn(self.eppn)
                assert user_after.terminated is not None

                self._audit_log_tests(assert_diff=self.assert_diff)
