from datetime import UTC, datetime
from uuid import UUID

import bson
from deepdiff import DeepDiff

from eduid.common.testing_base import normalised_data
from eduid.userdb.db.base import TUserDbDocument
from eduid.userdb.identity import IdentityType
from eduid.userdb.personal_data import PersonalDataUser
from eduid.userdb.proofing import ProofingUser
from eduid.userdb.reset_password import ResetPasswordUser
from eduid.userdb.security import SecurityUser
from eduid.workers.am.testing import ProofingTestCase


class AttributeFetcherNINProofingTests(ProofingTestCase):
    fetcher_name = "eduid_letter_proofing"

    def test_append_attributes_letter_proofing_data(self) -> None:
        self.user_data.update(
            {
                "letter_proofing_data": [
                    {
                        "verification_code": "secret code",
                        "verified": True,
                        "verified_by": "eduid-idproofing-letter",
                        "created_ts": "ts",
                        "official_address": {
                            "OfficialAddress": {
                                "PostalCode": "12345",
                                "City": "LANDET",
                                "Address2": "ÖRGATAN 79 LGH 10",
                            },
                            "Name": {"Surname": "Testsson", "GivenName": "Testaren Test", "GivenNameMarking": "20"},
                        },
                        "number": "123456781235",
                        "created_by": "eduid-idproofing-letter",
                        "verified_ts": "ts",
                        "transaction_id": "debug mode transaction id",
                    }
                ],
            }
        )
        proofing_user = ProofingUser.from_dict(self.user_data)

        assert self.fetcher
        assert self.fetcher.private_db

        self.fetcher.private_db.save(proofing_user)

        fetched = self.fetcher.fetch_attrs(proofing_user.user_id)

        expected = {
            "$set": {
                "givenName": "Testaren",
                "chosen_given_name": "Testaren",
                "surname": "Testsson",
                "legal_name": "Testaren Testsson",
                "identities": [
                    {
                        "identity_type": IdentityType.NIN.value,
                        "number": "123456781235",
                        "verified": True,
                        "created_ts": datetime(2022, 5, 18, 16, 36, 16, tzinfo=UTC),
                        "modified_ts": datetime(2022, 5, 18, 16, 36, 16, tzinfo=UTC),
                    }
                ],
                "letter_proofing_data": [
                    {
                        "verification_code": "secret code",
                        "verified": True,
                        "verified_by": "eduid-idproofing-letter",
                        "created_ts": "ts",
                        "official_address": {
                            "OfficialAddress": {
                                "PostalCode": "12345",
                                "City": "LANDET",
                                "Address2": "ÖRGATAN 79 LGH 10",
                            },
                            "Name": {
                                "Surname": "Testsson",
                                "GivenName": "Testaren Test",
                                "GivenNameMarking": "20",
                            },
                        },
                        "number": "123456781235",
                        "created_by": "eduid-idproofing-letter",
                        "verified_ts": "ts",
                        "transaction_id": "debug mode transaction id",
                    }
                ],
            },
            "$unset": {"nins": None},
        }

        assert normalised_data(fetched) == expected, (
            f"Fetched letter proofing data has unexpected data: {DeepDiff(fetched, expected)}"
        )

        fetched2 = self.fetcher.fetch_attrs(proofing_user.user_id)

        # Don't repeat the letter_proofing_data
        assert normalised_data(fetched2) == expected, (
            f"Fetched (2nd time) letter proofing data has unexpected data: {DeepDiff(fetched, expected)}"
        )

        # Adding a new letter_proofing_data
        self.user_data["letter_proofing_data"].append(
            {
                "verification_code": "secret code",
                "verified": True,
                "verified_by": "eduid-idproofing-letter",
                "created_ts": "ts",
                "official_address": {
                    "OfficialAddress": {"PostalCode": "12345", "City": "LANDET", "Address2": "ÖRGATAN 79 LGH 10"},
                    "Name": {"Surname": "Testsson", "GivenName": "Testaren Test", "GivenNameMarking": "20"},
                },
                "number": "123456781235",
                "created_by": "eduid-idproofing-letter",
                "verified_ts": "ts",
                "transaction_id": "debug mode transaction id",
            }
        )
        proofing_user = ProofingUser.from_dict(self.user_data)

        assert self.fetcher
        assert self.fetcher.private_db

        self.fetcher.private_db.save(proofing_user)

        fetched3 = self.fetcher.fetch_attrs(proofing_user.user_id)

        expected = {
            "$set": {
                "givenName": "Testaren",
                "chosen_given_name": "Testaren",
                "surname": "Testsson",
                "legal_name": "Testaren Testsson",
                "identities": [
                    {
                        "identity_type": IdentityType.NIN.value,
                        "number": "123456781235",
                        "verified": True,
                        "created_ts": datetime(2022, 5, 18, 16, 36, 16, tzinfo=UTC),
                        "modified_ts": datetime(2022, 5, 18, 16, 36, 16, tzinfo=UTC),
                    }
                ],
                "letter_proofing_data": [
                    {
                        "verification_code": "secret code",
                        "verified": True,
                        "verified_by": "eduid-idproofing-letter",
                        "created_ts": "ts",
                        "official_address": {
                            "OfficialAddress": {
                                "PostalCode": "12345",
                                "City": "LANDET",
                                "Address2": "ÖRGATAN 79 LGH 10",
                            },
                            "Name": {
                                "Surname": "Testsson",
                                "GivenName": "Testaren Test",
                                "GivenNameMarking": "20",
                            },
                        },
                        "number": "123456781235",
                        "created_by": "eduid-idproofing-letter",
                        "verified_ts": "ts",
                        "transaction_id": "debug mode transaction id",
                    },
                    {
                        "verification_code": "secret code",
                        "verified": True,
                        "verified_by": "eduid-idproofing-letter",
                        "created_ts": "ts",
                        "official_address": {
                            "OfficialAddress": {
                                "PostalCode": "12345",
                                "City": "LANDET",
                                "Address2": "ÖRGATAN 79 LGH 10",
                            },
                            "Name": {
                                "Surname": "Testsson",
                                "GivenName": "Testaren Test",
                                "GivenNameMarking": "20",
                            },
                        },
                        "number": "123456781235",
                        "created_by": "eduid-idproofing-letter",
                        "verified_ts": "ts",
                        "transaction_id": "debug mode transaction id",
                    },
                ],
            },
            "$unset": {"nins": None},
        }

        assert normalised_data(fetched3) == normalised_data(expected), (
            "Fetched (3d time) letter proofing data with appended attributes has unexpected data: "
            f"{DeepDiff(fetched, expected)}"
        )


class AttributeFetcherEmailProofingTests(ProofingTestCase):
    fetcher_name = "eduid_email"

    def test_existing_user(self) -> None:
        proofing_user = ProofingUser.from_dict(self.user_data)

        assert self.fetcher
        assert self.fetcher.private_db

        self.fetcher.private_db.save(proofing_user)

        fetched = self.fetcher.fetch_attrs(proofing_user.user_id)
        expected = {
            "$set": {"mailAliases": [{"email": "john@example.com", "verified": True, "primary": True}]},
        }

        assert normalised_data(fetched) == expected

    def test_fillup_attributes(self) -> None:
        self.user_data = TUserDbDocument(
            {
                "givenName": "Testaren",
                "surname": "Testsson",
                "preferredLanguage": "sv",
                "eduPersonPrincipalName": "test-test",
                "mailAliases": [{"email": "john@example.com", "verified": True, "primary": True}],
                "mobile": [{"verified": True, "mobile": "+46700011336", "primary": True}],
                "passwords": [
                    {
                        "id": bson.ObjectId("112345678901234567890123"),
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
            }
        )

        proofing_user = ProofingUser.from_dict(self.user_data)

        assert self.fetcher
        assert self.fetcher.private_db

        self.fetcher.private_db.save(proofing_user)

        fetched = self.fetcher.fetch_attrs(proofing_user.user_id)
        expected = {
            "$set": {"mailAliases": [{"email": "john@example.com", "verified": True, "primary": True}]},
        }

        assert normalised_data(fetched) == expected


class AttributeFetcherPhoneProofingTests(ProofingTestCase):
    fetcher_name = "eduid_phone"

    def test_existing_user(self) -> None:
        proofing_user = ProofingUser.from_dict(self.user_data)

        assert self.fetcher
        assert self.fetcher.private_db

        self.fetcher.private_db.save(proofing_user)
        fetched = self.fetcher.fetch_attrs(proofing_user.user_id)

        expected = {
            "$set": {"phone": [{"verified": True, "number": "+46700011336", "primary": True}]},
        }

        assert normalised_data(fetched) == expected, "Unexpected data fetched by phone fetcher for existing user"


class AttributeFetcherPersonalDataTests(ProofingTestCase):
    fetcher_name = "eduid_personal_data"

    def test_existing_user(self) -> None:
        personal_data_user = PersonalDataUser.from_dict(self.user_data)

        assert self.fetcher
        assert self.fetcher.private_db

        self.fetcher.private_db.save(personal_data_user)

        self.assertDictEqual(
            self.fetcher.fetch_attrs(personal_data_user.user_id),
            {
                "$set": {
                    "givenName": "Testaren",
                    "chosen_given_name": "Testaren",
                    "surname": "Testsson",
                    "preferredLanguage": "sv",
                    "preferences": {"always_use_security_key": True},
                },
            },
        )

    def test_fillup_attributes(self) -> None:
        # TODO: This test is IDENTICAL to the one above - need to actually add _more_ attributes in this one
        personal_data_user = PersonalDataUser.from_dict(self.user_data)

        assert self.fetcher
        assert self.fetcher.private_db

        self.fetcher.private_db.save(personal_data_user)

        self.assertDictEqual(
            self.fetcher.fetch_attrs(personal_data_user.user_id),
            {
                "$set": {
                    "givenName": "Testaren",
                    "chosen_given_name": "Testaren",
                    "surname": "Testsson",
                    "preferredLanguage": "sv",
                    "preferences": {"always_use_security_key": True},
                },
            },
        )


class AttributeFetcherSecurityTests(ProofingTestCase):
    fetcher_name = "eduid_security"

    def test_existing_user(self) -> None:
        security_user = SecurityUser.from_dict(self.user_data)

        assert self.fetcher
        assert self.fetcher.private_db

        self.fetcher.private_db.save(security_user)

        expected = {
            "$set": {
                "givenName": "Testaren",
                "chosen_given_name": "Testaren",
                "surname": "Testsson",
                "legal_name": "Testaren Testsson",
                "passwords": [
                    {
                        "credential_id": "112345678901234567890123",
                        "is_generated": False,
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
                "phone": [{"number": "+46700011336", "primary": True, "verified": True}],
            },
            "$unset": {"nins": None, "terminated": None},
        }
        fetched = self.fetcher.fetch_attrs(security_user.user_id)

        assert normalised_data(fetched) == expected, f"fetched does not match expected: {DeepDiff(fetched, expected)}"

    def test_fillup_attributes(self) -> None:
        security_user = SecurityUser.from_dict(self.user_data)

        assert self.fetcher
        assert self.fetcher.private_db

        self.fetcher.private_db.save(security_user)

        fetched = self.fetcher.fetch_attrs(security_user.user_id)

        expected = {
            "$set": {
                "givenName": "Testaren",
                "chosen_given_name": "Testaren",
                "surname": "Testsson",
                "legal_name": "Testaren Testsson",
                "passwords": [
                    {
                        "credential_id": "112345678901234567890123",
                        "is_generated": False,
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
                "phone": [{"number": "+46700011336", "primary": True, "verified": True}],
            },
            "$unset": {"nins": None, "terminated": None},
        }
        assert normalised_data(fetched) == expected, f"fetched does not match expected: {DeepDiff(fetched, expected)}"


class AttributeFetcherResetPasswordTests(ProofingTestCase):
    fetcher_name = "eduid_reset_password"

    def test_existing_user(self) -> None:
        reset_password_user = ResetPasswordUser.from_dict(self.user_data)

        assert self.fetcher
        assert self.fetcher.private_db

        self.fetcher.private_db.save(reset_password_user)

        fetched = self.fetcher.fetch_attrs(reset_password_user.user_id)

        expected = {
            "$set": {
                "passwords": [
                    {
                        "credential_id": "112345678901234567890123",
                        "is_generated": False,
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
                "phone": [{"number": "+46700011336", "primary": True, "verified": True}],
            },
            "$unset": {"nins": None, "terminated": None},
        }

        assert normalised_data(fetched) == expected, "Wrong data fetched by reset password fetcher"

    def test_fillup_attributes(self) -> None:
        # TODO: This test is IDENTICAL to the one above - need to actually add _more_ attributes in this one
        reset_password_user = ResetPasswordUser.from_dict(self.user_data)

        assert self.fetcher
        assert self.fetcher.private_db

        self.fetcher.private_db.save(reset_password_user)

        fetched = self.fetcher.fetch_attrs(reset_password_user.user_id)

        expected = {
            "$set": {
                "passwords": [
                    {
                        "credential_id": "112345678901234567890123",
                        "is_generated": False,
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
                "phone": [{"number": "+46700011336", "primary": True, "verified": True}],
            },
            "$unset": {"nins": None, "terminated": None},
        }

        assert normalised_data(fetched) == expected, "Wrong data fetched by reset password fetcher"


class AttributeFetcherOrcidTests(ProofingTestCase):
    fetcher_name = "eduid_orcid"

    def test_existing_user(self) -> None:
        proofing_user = ProofingUser.from_dict(self.user_data)

        assert self.fetcher
        assert self.fetcher.private_db

        self.fetcher.private_db.save(proofing_user)
        fetched = self.fetcher.fetch_attrs(proofing_user.user_id)

        expected = {
            "$set": {
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
                    "verified": True,
                    "id": "orcid_unique_id",
                    "created_by": "orcid",
                }
            },
        }

        assert normalised_data(fetched) == expected

    def test_remove_orcid(self) -> None:
        proofing_user = ProofingUser.from_dict(self.user_data)
        proofing_user.orcid = None

        assert self.fetcher
        assert self.fetcher.private_db

        self.fetcher.private_db.save(proofing_user)

        self.assertDictEqual(self.fetcher.fetch_attrs(proofing_user.user_id), {"$unset": {"orcid": None}})


class AttributeFetcherLadokTests(ProofingTestCase):
    fetcher_name = "eduid_ladok"

    def test_existing_user(self) -> None:
        proofing_user = ProofingUser.from_dict(self.user_data)

        assert self.fetcher
        assert self.fetcher.private_db

        self.fetcher.private_db.save(proofing_user)
        fetched = self.fetcher.fetch_attrs(proofing_user.user_id)

        expected = {
            "$set": {
                "ladok": {
                    "created_ts": datetime(2022, 2, 23, 17, 39, 32, tzinfo=UTC),
                    "modified_ts": datetime(2022, 2, 23, 17, 39, 32, tzinfo=UTC),
                    "verified_by": "eduid-ladok",
                    "external_id": UUID("9555f3de-dd32-4bed-8e36-72ef00fb4df2"),
                    "university": {
                        "created_ts": datetime(2022, 2, 23, 17, 39, 32, tzinfo=UTC),
                        "modified_ts": datetime(2022, 2, 23, 17, 39, 32, tzinfo=UTC),
                        "ladok_name": "ab",
                        "name": {"sv": "Lärosätesnamn", "en": "University Name"},
                    },
                    "verified": True,
                }
            }
        }

        expected = {
            "$set": {
                "ladok": self.user_data["ladok"],
            }
        }

        assert normalised_data(fetched) == normalised_data(expected)

    def test_remove_ladok(self) -> None:
        proofing_user = ProofingUser.from_dict(self.user_data)
        proofing_user.ladok = None

        assert self.fetcher
        assert self.fetcher.private_db

        self.fetcher.private_db.save(proofing_user)

        self.assertDictEqual(self.fetcher.fetch_attrs(proofing_user.user_id), {"$unset": {"ladok": None}})
