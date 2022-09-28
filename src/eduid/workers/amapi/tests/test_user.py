# -*- coding: utf-8 -*-

__author__ = "masv"

import json
from typing import Dict, Optional

import pkg_resources
from bson import ObjectId

from eduid.common.testing_base import CommonTestCase
from fastapi.testclient import TestClient

from eduid.userdb.fixtures.users import (
    new_user_example,
)
from eduid.workers.amapi.app import init_api


class TestAMBase(CommonTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        self.path = pkg_resources.resource_filename(__name__, "data")
        self.test_config = self._get_config()

        self.api = init_api(name="test_api", test_config=self.test_config)
        self.client = TestClient(self.api)
        self.eppn = "hubba-bubba"
        self.source = "mura"
        self.reason = "mura"

    def _get_config(self) -> Dict:
        config = {
            "keystore_path": f"{self.path}/testing_jwks.json",
            "mongo_uri": self.settings["mongo_uri"],
        }
        return config

    @staticmethod
    def as_json(data: dict) -> str:
        return json.dumps(data)


class TestUsers(TestAMBase):
    def setUp(self, *args, **kwargs):
        super().setUp(am_users=[new_user_example])

    def _make_url(self, endpoint: Optional[str] = None) -> str:
        if endpoint is None:
            return f"/users/{self.eppn}"
        return f"/users/{self.eppn}/{endpoint}"

    def _audit_log_tests(self, assert_diff: dict):
        audit_log = self.api.audit_logger.get_by_eppn(self.eppn)
        assert audit_log is not None
        assert audit_log.eppn == self.eppn
        assert audit_log.reason == self.reason
        assert audit_log.source == self.source
        assert audit_log.diff == self.as_json(assert_diff)

    def make_put_call(self, req: dict, endpoint: Optional[str] = None):
        response = self.client.put(
            url=self._make_url(endpoint),
            data=self.as_json(req),
        )
        assert response.status_code == 200

    def make_delete_call(self, req: dict, endpoint: Optional[str] = None):
        response = self.client.delete(
            url=self._make_url(endpoint),
            data=self.as_json(req),
        )
        assert response.status_code == 200

    def test_update_name(self):
        req = {
            "reason": self.reason,
            "source": self.source,
            "given_name": None,
            "display_name": "test_display_name",
            "surname": "Smith",
        }

        assert_diff = {
            "dictionary_item_removed": ["root['givenName']"],
            "values_changed": {
                "root['displayName']": {
                    "new_value": "test_display_name",
                    "old_value": "John Smith",
                },
            },
        }

        self.make_put_call(req, "name")

        user_after = self.amdb.get_user_by_eppn(self.eppn)
        assert user_after.given_name is None
        assert user_after.display_name == "test_display_name"
        assert user_after.surname == "Smith"
        assert user_after.meta.version is not ObjectId("987654321098765432103210")

        self._audit_log_tests(assert_diff=assert_diff)

    def test_update_meta(self):
        pass

    def test_update_email(self):
        req = {
            "reason": self.reason,
            "source": self.source,
            "mail_addresses": [
                {
                    "email": "test@example.com",
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

        assert_diff = {
            "values_changed": {
                "root['mailAliases'][0]": {
                    "new_value": {
                        "created_by": "signup",
                        "created_ts": "2013-09-02T10:23:25",
                        "modified_ts": "2013-09-02T10:23:25",
                        "verified_by": "signup",
                        "verified_ts": "2013-09-02T10:23:25",
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

        self.make_put_call(req, "email")

        user_after = self.amdb.get_user_by_eppn(self.eppn)
        assert user_after.mail_addresses.to_list()[0].email == "test@example.com"
        assert len(user_after.mail_addresses.to_list()) == 1

        self._audit_log_tests(assert_diff=assert_diff)

    def test_update_language(self):
        req = {"reason": self.reason, "source": self.source, "language": "test"}

        assert_diff = {
            "values_changed": {
                "root['preferredLanguage']": {
                    "new_value": "test",
                    "old_value": "en",
                },
            },
        }

        self.make_put_call(req, "language")

        user_after = self.amdb.get_user_by_eppn(self.eppn)
        assert user_after.language == "test"

        self._audit_log_tests(assert_diff=assert_diff)

    def test_update_phone(self):
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

        assert_diff = {
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

        self.make_put_call(req, "phone")

        user_after = self.amdb.get_user_by_eppn(self.eppn)
        assert user_after.phone_numbers.to_list()[0].number == "08197806"

        self._audit_log_tests(assert_diff=assert_diff)

    def test_terminate(self):
        req = {
            "source": self.source,
            "reason": self.reason,
        }

        assert_diff = {
            "dictionary_item_added": ["root['terminated']"],
        }

        self.make_delete_call(req)

        user_after = self.amdb.get_user_by_eppn(self.eppn)
        assert user_after.terminated is not None

        self._audit_log_tests(assert_diff=assert_diff)
