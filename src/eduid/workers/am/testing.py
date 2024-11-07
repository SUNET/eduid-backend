"""
Code used in unit tests of various eduID applications.
"""

__author__ = "leifj"

import logging
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import bson
import pytest
from pydantic import ValidationError

from eduid.common.config.base import AmConfigMixin, EduIDBaseAppConfig
from eduid.common.config.workers import AmConfig
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.testing_base import CommonTestCase
from eduid.userdb.db import TUserDbDocument
from eduid.userdb.exceptions import UserDoesNotExist
from eduid.userdb.identity import IdentityType
from eduid.userdb.proofing import ProofingUser
from eduid.userdb.testing import MongoTemporaryInstance, SetupConfig
from eduid.userdb.userdb import UserDB
from eduid.workers.am.ams import AttributeFetcher
from eduid.workers.am.common import AmCelerySingleton

logger = logging.getLogger(__name__)


USER_DATA = TUserDbDocument(
    {
        "givenName": "Testaren",
        "chosen_given_name": "Testaren",
        "surname": "Testsson",
        "legal_name": "Testaren Testsson",
        "preferredLanguage": "sv",
        "eduPersonPrincipalName": "test-test",
        "mailAliases": [{"email": "john@example.com", "verified": True}],
        "mobile": [{"verified": True, "mobile": "+46700011336", "primary": True}],
        "passwords": [
            {
                "credential_id": "112345678901234567890123",
                "salt": "$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$",
            }
        ],
        "identities": [
            {
                "identity_type": IdentityType.NIN.value,
                "number": "123456781235",
                "verified": True,
                "created_ts": datetime(2022, 5, 18, 16, 36, 16, tzinfo=UTC),
                "modified_ts": datetime(2022, 5, 18, 16, 36, 16, tzinfo=UTC),
            }
        ],
        "orcid": {
            "oidc_authz": {
                "token_type": "bearer",
                "refresh_token": "a_refresh_token",
                "access_token": "an_access_token",
                "id_token": {
                    "nonce": "a_nonce",
                    "sub": "sub_id",
                    "iss": "https://issuer.example.org",
                    "created_by": "orcid",
                    "exp": 1526890816,
                    "auth_time": 1526890214,
                    "iat": 1526890216,
                    "aud": ["APP-YIAD0N1L4B3Z3W9Q"],
                },
                "expires_in": 631138518,
                "created_by": "orcid",
            },
            "given_name": "Testaren",
            "family_name": "Testsson",
            "name": None,
            "id": "orcid_unique_id",
            "verified": True,
            "created_by": "orcid",
        },
        "ladok": {
            "created_ts": datetime(2022, 2, 23, 17, 39, 32, 303000, tzinfo=UTC),
            "modified_ts": datetime(2022, 2, 23, 17, 39, 32, 303000, tzinfo=UTC),
            "verified_by": "eduid-ladok",
            "external_id": UUID("9555f3de-dd32-4bed-8e36-72ef00fb4df2"),
            "university": {
                "created_ts": datetime(2022, 2, 23, 17, 39, 32, 303000, tzinfo=UTC),
                "modified_ts": datetime(2022, 2, 23, 17, 39, 32, 303000, tzinfo=UTC),
                "ladok_name": "ab",
                "name": {"sv": "Lärosätesnamn", "en": "University Name"},
            },
            "verified": True,
        },
    }
)


class AmTestConfig(EduIDBaseAppConfig, AmConfigMixin):
    pass


class WorkerTestCase(CommonTestCase):
    """
    Base Test case for eduID celery workers
    """

    def setUp(self, config: SetupConfig | None = None) -> None:
        """
        set up tests
        """
        super().setUp(config=config)

        settings: dict[str, Any] = {
            "app_name": "testing",
            "celery": {
                "broker_transport": "memory",
                "broker_url": "memory://",
                "task_eager_propagates": True,
                "task_always_eager": True,
                "result_backend": "cache",
                "cache_backend": "memory",
            },
            # Be sure to NOT tell AttributeManager about the temporary mongodb instance.
            # If we do, one or more plugins may open DB connections that never gets closed.
            "mongo_uri": None,
        }

        if config is None:
            config = SetupConfig()
        if config.am_settings:
            settings.update(config.am_settings)
        if config.want_mongo_uri:
            assert isinstance(self.tmp_db, MongoTemporaryInstance)  # please mypy
            settings["mongo_uri"] = self.tmp_db.uri

        am_config = AmTestConfig(**settings)
        AmCelerySingleton.update_worker_config(AmConfig(**settings))

        self.am_relay = AmRelay(am_config)


class AMTestCase(WorkerTestCase):
    """TestCase with an embedded Attribute Manager."""

    def tearDown(self) -> None:
        for fetcher in AmCelerySingleton.af_registry.all_fetchers():
            if fetcher.private_db:
                fetcher.private_db._drop_whole_collection()
        super().tearDown()


class ProofingTestCase(AMTestCase):
    fetcher_name: str | None = None
    fetcher: AttributeFetcher | None = None

    def setUp(self, config: SetupConfig | None = None) -> None:
        super().setUp(config=config)

        if self.fetcher_name:
            self.fetcher = AmCelerySingleton.af_registry.get_fetcher(self.fetcher_name)

        self.user_data = deepcopy(USER_DATA)

        # Copy all user documents from the AM database into the private database used
        # by _all_ the fetchers available through self.af_registry.
        for userdoc in self.amdb._get_all_docs():
            proofing_user = ProofingUser.from_dict(userdoc)
            for fetcher in AmCelerySingleton.af_registry.all_fetchers():
                assert fetcher.private_db
                fetcher.private_db.save(proofing_user)

    def test_invalid_user(self) -> None:
        if self.fetcher is None:
            pytest.skip("Fetcher not initialised")
        assert self.fetcher  # mypy doesn't understand pytest.skip it seems

        with self.assertRaises(UserDoesNotExist):
            self.fetcher.fetch_attrs(bson.ObjectId("0" * 24))

    def test_malicious_attributes(self) -> None:
        if self.fetcher is None:
            pytest.skip("Fetcher not initialised")
        assert self.fetcher  # mypy doesn't understand pytest.skip it seems

        self.user_data.update({"malicious": "hacker"})

        # Write bad entry into database
        assert isinstance(self.fetcher.private_db, UserDB)
        result = self.fetcher.private_db._coll.insert_one(TUserDbDocument(self.user_data))
        user_id = result.inserted_id

        with self.assertRaises(ValidationError):
            self.fetcher.fetch_attrs(user_id)
