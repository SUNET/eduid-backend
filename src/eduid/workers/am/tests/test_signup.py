from copy import deepcopy

import bson
from pydantic import ValidationError

from eduid.common.testing_base import normalised_data
from eduid.userdb.exceptions import UserDoesNotExist
from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.signup import SignupUser
from eduid.userdb.testing import SetupConfig
from eduid.userdb.user import User
from eduid.workers.am.common import AmCelerySingleton
from eduid.workers.am.testing import USER_DATA, AMTestCase


class AttributeFetcherTests(AMTestCase):
    user: User

    def setUp(self, config: SetupConfig | None = None) -> None:
        am_settings = {"new_user_date": "2001-01-01"}
        self.user = UserFixtures().mocked_user_standard
        if config is None:
            config = SetupConfig()
        config.am_users = [self.user]
        config.am_settings = am_settings
        super().setUp(config=config)

        self.fetcher = AmCelerySingleton.af_registry.get_fetcher("eduid_signup")

        assert self.fetcher.private_db

        for userdoc in self.amdb._get_all_docs():
            signup_user = SignupUser.from_dict(userdoc)
            self.fetcher.private_db.save(signup_user)

    def test_invalid_user(self) -> None:
        with self.assertRaises(UserDoesNotExist):
            self.fetcher.fetch_attrs(bson.ObjectId("000000000000000000000000"))

    def test_existing_user_from_db(self) -> None:
        fetched = self.fetcher.fetch_attrs(self.user.user_id)

        expected_passwords = self.user.credentials.to_list_of_dicts()
        expected_emails = self.user.mail_addresses.to_list_of_dicts()
        expected_phones = self.user.phone_numbers.to_list_of_dicts()
        expected_identities = self.user.identities.to_list_of_dicts()

        expected = {
            "$set": {
                "eduPersonPrincipalName": self.user.eppn,
                "mailAliases": expected_emails,
                "phone": expected_phones,
                "passwords": expected_passwords,
                "identities": expected_identities,
                "givenName": self.user.given_name,
                "surname": self.user.surname,
                "preferredLanguage": self.user.language,
            }
        }

        # normalise expected too since otherwise expected timestamps won't have timezone, but fetched timestamps will
        expected = normalised_data(expected)

        assert normalised_data(fetched) == expected

    def test_existing_user(self) -> None:
        user_data = deepcopy(USER_DATA)
        user_data["mail"] = "johnsmith@example.com"
        user_data["mailAliases"] = [{"verified": True, "email": "johnsmith@example.com"}]
        del user_data["passwords"]
        user = SignupUser.from_dict(user_data)
        assert self.fetcher.private_db
        self.fetcher.private_db.save(user)
        with self.assertRaises(ValueError):
            self.fetcher.fetch_attrs(bson.ObjectId(user.user_id))

    def test_user_without_aliases(self) -> None:
        user_data = deepcopy(USER_DATA)
        user_data["mail"] = "johnsmith@example.com"
        del user_data["passwords"]
        user = SignupUser.from_dict(user_data)
        assert self.fetcher.private_db
        self.fetcher.private_db.save(user)
        with self.assertRaises(ValueError):
            self.fetcher.fetch_attrs(bson.ObjectId(user.user_id))

    def test_user_finished_and_removed(self) -> None:
        user_data = deepcopy(USER_DATA)
        user_data["mail"] = "john@example.com"
        user_data["mailAliases"] = [
            {
                "email": "john@example.com",
                "verified": True,
            }
        ]
        user_data["passwords"] = [
            {
                "id": "123",
                "salt": "456",
            }
        ]
        user = SignupUser.from_dict(user_data)
        assert self.fetcher.private_db
        self.fetcher.private_db.save(user)

        fetched = self.fetcher.fetch_attrs(user.user_id)

        expected_passwords = [
            {
                "credential_id": "123",
                "is_generated": False,
                "salt": "456",
                "version": 1,
            }
        ]

        expected_emails = [{"verified": True, "primary": True, "email": "john@example.com"}]
        expected_phones = user.phone_numbers.to_list_of_dicts()
        expected_identities = user.identities.to_list_of_dicts()

        expected = {
            "$set": {
                "eduPersonPrincipalName": user.eppn,
                "mailAliases": expected_emails,
                "passwords": expected_passwords,
                "phone": expected_phones,
                "identities": expected_identities,
                "givenName": user.given_name,
                "surname": user.surname,
                "preferredLanguage": user.language,
            }
        }

        # XXX: Why did this change? Investigate.
        # normalise expected too since otherwise enum values and other types won't match normalised fetched data
        expected = normalised_data(expected)

        assert normalised_data(fetched) == expected, "Wrong data fetched by signup fetcher"

    def test_malicious_attributes(self) -> None:
        user_data = deepcopy(USER_DATA)
        user_data["foo"] = "bar"
        user_data["mail"] = "john@example.com"
        user_data["mailAliases"] = [
            {
                "email": "john@example.com",
                "verified": True,
            }
        ]
        user_data["passwords"] = [
            {
                "id": "123",
                "salt": "456",
            }
        ]
        with self.assertRaises(ValidationError):
            SignupUser.from_dict(user_data)
