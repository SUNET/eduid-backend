__author__ = "masv"

import datetime
from typing import Any

from bson import ObjectId
from fastapi import status
from httpx import Headers, Response
from jwcrypto import jwt

from eduid.common.clients.gnap_client.base import GNAPBearerTokenMixin
from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.meta import CleanerType
from eduid.userdb.testing import SetupConfig
from eduid.workers.amapi.testing import TestAMBase
from eduid.workers.amapi.utils import AuthnBearerToken


class TestUsers(TestAMBase, GNAPBearerTokenMixin):
    def setUp(self, config: SetupConfig | None = None) -> None:
        _am_users = [UserFixtures().new_user_example]
        if config is None:
            config = SetupConfig()
        config.am_users = _am_users
        super().setUp(config=config)

    def _make_url(self, endpoint: str | None = None) -> str:
        if endpoint is None:
            return f"/users/{self.eppn}"
        return f"/users/{self.eppn}/{endpoint}"

    def _check_audit_log(self, diff: dict[str, Any]) -> None:
        audit_logs = self.api.context.audit_logger.get_by_eppn(self.eppn)
        assert len(audit_logs) == 1
        assert audit_logs[0].eppn == self.eppn
        assert audit_logs[0].reason == self.reason
        assert audit_logs[0].source == self.source
        assert audit_logs[0].diff == self.as_json(diff)

    def make_put_call(self, json_data: dict, oauth_header: Headers, endpoint: str | None = None) -> Response:
        response = self.client.put(
            url=self._make_url(endpoint),
            json=json_data,
            headers=oauth_header,
        )
        return response

    def _auth_header(self, service_name: str) -> Headers:
        expire = datetime.timedelta(seconds=3600)
        signing_key = self.api.context.jwks.get_key(self.test_singing_key)
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

    def test_update_name_allowed(self) -> None:
        req = {
            "reason": self.reason,
            "source": self.source,
            "given_name": None,
            "legal_name": "Testsson",
            "surname": "Testsson",
        }
        expected_audit_diff = {
            "dictionary_item_added": ["root['legal_name']"],
            "dictionary_item_removed": ["root['givenName']"],
            "values_changed": {
                "root['surname']": {
                    "new_value": "Testsson",
                    "old_value": "Smith",
                },
            },
        }
        got = self.make_put_call(
            json_data=req,
            oauth_header=self._auth_header("test-service_name"),
            endpoint="name",
        )
        assert got.status_code == status.HTTP_200_OK
        user_after = self.amdb.get_user_by_eppn(self.eppn)
        assert user_after.given_name is None
        assert user_after.legal_name == "Testsson"
        assert user_after.surname == "Testsson"
        assert user_after.meta.version is not ObjectId("987654321098765432103210")

        self._check_audit_log(diff=expected_audit_diff)

    def test_update_name_not_allowed(self) -> None:
        req = {
            "reason": self.reason,
            "source": self.source,
            "given_name": None,
            "display_name": "test_display_name",
            "surname": "Smith",
        }
        got = self.make_put_call(
            json_data=req,
            oauth_header=self._auth_header("wrong_service_name"),
            endpoint="name",
        )
        assert got.status_code == status.HTTP_401_UNAUTHORIZED

    def test_update_email_allowed(self) -> None:
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

        expected_audit_diff = {
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
        got = self.make_put_call(
            json_data=req,
            oauth_header=self._auth_header(service_name="test-service_name"),
            endpoint="email",
        )
        assert got.status_code == status.HTTP_200_OK
        user_after = self.amdb.get_user_by_eppn(self.eppn)
        assert user_after.mail_addresses.to_list()[0].email == "test@example.com"
        assert len(user_after.mail_addresses.to_list()) == 1

        self._check_audit_log(diff=expected_audit_diff)

    def test_update_email_not_allowed(self) -> None:
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
        got = self.make_put_call(
            json_data=req,
            oauth_header=self._auth_header(service_name="wrong-service_name"),
            endpoint="email",
        )
        assert got.status_code == status.HTTP_401_UNAUTHORIZED

    def test_update_language_allowed(self) -> None:
        req = {
            "reason": self.reason,
            "source": self.source,
            "language": "test",
        }

        expected_audit_diff = {
            "values_changed": {
                "root['preferredLanguage']": {
                    "new_value": "test",
                    "old_value": "en",
                },
            },
        }

        got = self.make_put_call(
            json_data=req,
            oauth_header=self._auth_header(service_name="test-service_name"),
            endpoint="language",
        )
        assert got.status_code == status.HTTP_200_OK
        user_after = self.amdb.get_user_by_eppn(self.eppn)
        assert user_after.language == "test"

        self._check_audit_log(diff=expected_audit_diff)

    def test_update_language_not_allowed(self) -> None:
        req = {
            "reason": self.reason,
            "source": self.source,
            "language": "test",
        }
        got = self.make_put_call(
            json_data=req,
            oauth_header=self._auth_header(service_name="wrong-service_name"),
            endpoint="language",
        )
        assert got.status_code == status.HTTP_401_UNAUTHORIZED

    def test_update_phone_allowed(self) -> None:
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
        expected_audit_diff = {
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
        got = self.make_put_call(
            json_data=req,
            oauth_header=self._auth_header(service_name="test-service_name"),
            endpoint="phone",
        )

        assert got.status_code == status.HTTP_200_OK
        user_after = self.amdb.get_user_by_eppn(self.eppn)
        assert user_after.phone_numbers.to_list()[0].number == "08197806"

        self._check_audit_log(diff=expected_audit_diff)

    def test_update_phone_not_allowed(self) -> None:
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
        got = self.make_put_call(
            json_data=req,
            oauth_header=self._auth_header(service_name="wrong-service_name"),
            endpoint="phone",
        )

        assert got.status_code == status.HTTP_401_UNAUTHORIZED

    def test_update_meta_cleaned_custom_ts(self) -> None:
        req = {
            "source": self.source,
            "reason": self.reason,
            "type": "skatteverket",
            "ts": "2013-09-02T10:23:25+00:00",
        }

        user_before = self.amdb.get_user_by_eppn(self.eppn)
        got = self.make_put_call(
            json_data=req,
            oauth_header=self._auth_header(service_name="test-service_name"),
            endpoint="meta/cleaned",
        )
        assert got.status_code == status.HTTP_200_OK
        user_after = self.amdb.get_user_by_eppn(self.eppn)
        assert user_before.meta.cleaned
        assert user_after.meta.cleaned
        assert user_after.meta.cleaned[CleanerType.SKV] != user_before.meta.cleaned[CleanerType.SKV]
        expected_audit_diff = {
            "values_changed": {
                "root['meta']['cleaned']['skatteverket']": {
                    "new_value": "2013-09-02T10:23:25+00:00",
                    "old_value": "2017-01-04T16:47:30+00:00",
                }
            }
        }

        self._check_audit_log(diff=expected_audit_diff)

    def test_update_meta_cleaned_auto_ts(self) -> None:
        req = {
            "source": self.source,
            "reason": self.reason,
            "type": CleanerType.SKV,
        }

        user_before = self.amdb.get_user_by_eppn(self.eppn)
        got = self.make_put_call(
            json_data=req,
            oauth_header=self._auth_header(service_name="test-service_name"),
            endpoint="meta/cleaned",
        )
        assert got.status_code == status.HTTP_200_OK
        user_after = self.amdb.get_user_by_eppn(self.eppn)
        assert user_before.meta.cleaned
        assert user_after.meta.cleaned
        assert user_after.meta.cleaned[CleanerType.SKV] != user_before.meta.cleaned[CleanerType.SKV]

    def test_update_meta_cleaned_not_allowed(self) -> None:
        req = {
            "source": self.source,
            "reason": self.reason,
            "type": "skatteverket",
        }

        got = self.make_put_call(
            json_data=req,
            oauth_header=self._auth_header(service_name="wrong-service_name"),
            endpoint="meta/cleaned",
        )
        assert got.status_code == status.HTTP_401_UNAUTHORIZED

    def test_update_terminate_allowed(self) -> None:
        req = {
            "source": self.source,
            "reason": self.reason,
        }
        expected_audit_diff = {
            "dictionary_item_added": ["root['terminated']"],
        }

        got = self.make_put_call(
            json_data=req,
            oauth_header=self._auth_header(service_name="test-service_name"),
            endpoint="terminate",
        )

        assert got.status_code == status.HTTP_200_OK
        user_after = self.amdb.get_user_by_eppn(self.eppn)
        assert user_after.terminated is not None

        self._check_audit_log(diff=expected_audit_diff)

    def test_update_terminate_not_allowed(self) -> None:
        req = {
            "source": self.source,
            "reason": self.reason,
        }
        got = self.make_put_call(
            json_data=req,
            oauth_header=self._auth_header(service_name="wrong-service_name"),
            endpoint="terminate",
        )

        assert got.status_code == status.HTTP_401_UNAUTHORIZED
