#
# Copyright (c) 2019 SUNET
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

"""
Code used in unit tests of various eduID applications.
"""

__author__ = "leifj"

import logging
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, Optional
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
from eduid.userdb.testing import MongoTemporaryInstance
from eduid.userdb.userdb import UserDB
from eduid.workers.am.ams import AttributeFetcher
from eduid.workers.am.common import AmCelerySingleton

logger = logging.getLogger(__name__)


USER_DATA = TUserDbDocument(
    {
        "givenName": "Testaren",
        "surname": "Testsson",
        "displayName": "John",
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
                "created_ts": datetime(2022, 5, 18, 16, 36, 16, tzinfo=timezone.utc),
                "modified_ts": datetime(2022, 5, 18, 16, 36, 16, tzinfo=timezone.utc),
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
            "created_ts": datetime(2022, 2, 23, 17, 39, 32, 303000, tzinfo=timezone.utc),
            "modified_ts": datetime(2022, 2, 23, 17, 39, 32, 303000, tzinfo=timezone.utc),
            "verified_by": "eduid-ladok",
            "external_id": UUID("9555f3de-dd32-4bed-8e36-72ef00fb4df2"),
            "university": {
                "created_ts": datetime(2022, 2, 23, 17, 39, 32, 303000, tzinfo=timezone.utc),
                "modified_ts": datetime(2022, 2, 23, 17, 39, 32, 303000, tzinfo=timezone.utc),
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

    def setUp(self, *args, am_settings: Optional[Dict[str, Any]] = None, want_mongo_uri: bool = True, **kwargs):
        """
        set up tests
        """
        super().setUp(*args, **kwargs)

        settings = {
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
            "token_service_url": "foo",
        }

        if am_settings:
            settings.update(am_settings)
        if want_mongo_uri:
            assert isinstance(self.tmp_db, MongoTemporaryInstance)  # please mypy
            settings["mongo_uri"] = self.tmp_db.uri

        am_config = AmTestConfig(**settings)
        AmCelerySingleton.update_worker_config(AmConfig(**settings))

        self.am_relay = AmRelay(am_config)


class AMTestCase(WorkerTestCase):
    """TestCase with an embedded Attribute Manager."""

    def tearDown(self):
        for fetcher in AmCelerySingleton.af_registry.all_fetchers():
            if fetcher.private_db:
                fetcher.private_db._drop_whole_collection()
        super().tearDown()


class ProofingTestCase(AMTestCase):

    fetcher_name: Optional[str] = None
    fetcher: Optional[AttributeFetcher] = None

    def setUp(self, **kwargs):
        super().setUp(**kwargs)

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

    def test_invalid_user(self):
        if self.fetcher is None:
            pytest.skip("Fetcher not initialised")
        assert self.fetcher  # mypy doesn't understand pytest.skip it seems

        with self.assertRaises(UserDoesNotExist):
            self.fetcher.fetch_attrs(bson.ObjectId("0" * 24))

    def test_malicious_attributes(self):
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
