from bson import ObjectId

import eduid.userdb
from eduid.common.testing_base import normalised_data
from eduid.userdb import LockedIdentityList, NinIdentity
from eduid.userdb.exceptions import EduIDUserDBError, MultipleUsersReturned
from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.identity import IdentityType
from eduid.userdb.testing import SetupConfig
from eduid.userdb.user import User
from eduid.workers.am.consistency_checks import check_locked_identity, unverify_duplicates
from eduid.workers.am.testing import AMTestCase


class TestTasks(AMTestCase):
    user: User

    def setUp(self, config: SetupConfig | None = None) -> None:
        _users = UserFixtures()
        self.user = _users.mocked_user_standard
        _am_users = [self.user, _users.mocked_user_standard_2]
        if config is None:
            config = SetupConfig()
        config.want_mongo_uri = True
        config.am_users = _am_users
        super().setUp(config=config)

    def test_get_user_by_id(self) -> None:
        user = self.amdb.get_user_by_id(self.user.user_id)
        assert user
        assert user.mail_addresses.primary
        assert self.user.mail_addresses.primary
        self.assertEqual(user.mail_addresses.primary.email, self.user.mail_addresses.primary.email)
        assert not self.amdb.get_user_by_id("123456789012")

    def test_get_user_by_mail(self) -> None:
        assert self.user.mail_addresses.primary
        user = self.amdb.get_user_by_mail(self.user.mail_addresses.primary.email)
        assert user
        self.assertEqual(user.user_id, self.user.user_id)

        _unverified = [x for x in self.user.mail_addresses.to_list() if not x.is_verified]

        # Test unverified mail address in mailAliases, should raise UserDoesNotExist
        assert self.amdb.get_user_by_mail(_unverified[0].email) is None

    def test_user_duplication_exception(self) -> None:
        assert self.user.mail_addresses.primary
        user1 = self.amdb.get_user_by_mail(self.user.mail_addresses.primary.email)
        assert user1
        user2_doc = user1.to_dict()
        user2_doc["_id"] = ObjectId()  # make up a new unique identifier
        del user2_doc["modified_ts"]  # defeat sync-check mechanism
        self.amdb.save(eduid.userdb.User.from_dict(user2_doc))
        with self.assertRaises(MultipleUsersReturned):
            self.amdb.get_user_by_mail(self.user.mail_addresses.primary.email)

    def test_unverify_duplicate_mail(self) -> None:
        user_id = ObjectId("901234567890123456789012")  # johnsmith@example.org / babba-labba
        attributes = {
            "$set": {
                "mailAliases": [
                    {
                        "email": "johnsmith@example.com",  # hubba-bubba's primary mail address
                        "verified": True,
                        "primary": True,
                        "created_ts": True,
                    }
                ]
            }
        }
        stats = unverify_duplicates(self.amdb, user_id, attributes)
        user = self.amdb.get_user_by_eppn("hubba-bubba")
        assert user
        assert user.mail_addresses.primary
        self.assertNotEqual(user.mail_addresses.primary.email, "johnsmith@example.com")
        primary_mail = user.mail_addresses.find("johnsmith@example.com")
        assert primary_mail
        self.assertFalse(primary_mail.is_verified)
        self.assertTrue(user.mail_addresses.primary)
        self.assertEqual(stats["mail_count"], 1)

    def test_unverify_duplicate_phone(self) -> None:
        user_id = ObjectId("901234567890123456789012")  # johnsmith@example.org / babba-labba
        attributes = {
            "$set": {
                "phone": [{"verified": True, "number": "+34609609609", "primary": True}]  # hubba-bubba's primary phone
            }
        }
        stats = unverify_duplicates(self.amdb, user_id, attributes)
        user = self.amdb.get_user_by_eppn("hubba-bubba")
        assert user
        assert user.phone_numbers.primary
        self.assertNotEqual(user.phone_numbers.primary.number, "+34609609609")
        primary_phone = user.phone_numbers.find("+34609609609")
        assert primary_phone
        self.assertFalse(primary_phone.is_verified)
        self.assertTrue(user.phone_numbers.primary)
        self.assertEqual(stats["phone_count"], 1)

    def test_unverify_duplicate_nins(self) -> None:
        user_id = ObjectId("901234567890123456789012")  # johnsmith@example.org / babba-labba
        attributes = {
            "$set": {
                "identities": [
                    {
                        "identity_type": IdentityType.NIN.value,
                        "verified": True,
                        "number": "197801011234",
                    }  # hubba-bubba's nin
                ]
            }
        }
        stats = unverify_duplicates(self.amdb, user_id, attributes)
        user = self.amdb.get_user_by_eppn("hubba-bubba")
        assert user.identities.nin is not None
        assert user.identities.nin.number == "197801011234"
        assert user.identities.nin.is_verified is False
        self.assertEqual(stats["nin_count"], 1)

    def test_unverify_duplicate_all(self) -> None:
        user_id = ObjectId("901234567890123456789012")  # johnsmith@example.org / babba-labba
        attributes = {
            "$set": {
                "mailAliases": [
                    {
                        "email": "johnsmith@example.com",  # hubba-bubba's primary mail address
                        "verified": True,
                        "primary": True,
                        "created_ts": True,
                    }
                ],
                "phone": [{"verified": True, "number": "+34609609609", "primary": True}],  # hubba-bubba's primary phone
                "identities": [
                    {
                        "identity_type": IdentityType.NIN.value,
                        "verified": True,
                        "number": "197801011234",
                    }  # hubba-bubba's nin
                ],
            }
        }
        stats = unverify_duplicates(self.amdb, user_id, attributes)
        user = self.amdb.get_user_by_eppn("hubba-bubba")
        assert user
        assert user.mail_addresses.primary

        self.assertNotEqual(user.mail_addresses.primary.email, "johnsmith@example.com")
        primary_mail = user.mail_addresses.find("johnsmith@example.com")
        assert primary_mail
        self.assertFalse(primary_mail.is_verified)
        self.assertTrue(user.mail_addresses.primary)

        assert user.phone_numbers.primary
        self.assertNotEqual(user.phone_numbers.primary.number, "+34609609609")
        primary_phone = user.phone_numbers.find("+34609609609")
        assert primary_phone
        self.assertFalse(primary_phone.is_verified)
        self.assertTrue(user.phone_numbers.primary)

        assert user.identities.nin is not None
        assert user.identities.nin.number == "197801011234"
        assert user.identities.nin.is_verified is False

        self.assertEqual(stats["mail_count"], 1)
        self.assertEqual(stats["phone_count"], 1)
        self.assertEqual(stats["nin_count"], 1)

    def test_unverify_duplicate_multiple_attribute_values(self) -> None:
        user_id = ObjectId("901234567890123456789012")  # johnsmith@example.org / babba-labba
        attributes = {
            "$set": {
                "mailAliases": [
                    {"email": "johnsmith@example.net", "verified": True, "primary": True, "created_ts": True},
                    {
                        "email": "johnsmith@example.com",  # hubba-bubba's primary mail address
                        "verified": True,
                        "primary": True,
                        "created_ts": True,
                    },
                ]
            }
        }
        stats = unverify_duplicates(self.amdb, user_id, attributes)
        user = self.amdb.get_user_by_eppn("hubba-bubba")
        assert user
        assert user.mail_addresses.primary
        self.assertNotEqual(user.mail_addresses.primary.email, "johnsmith@example.com")
        primary_mail = user.mail_addresses.find("johnsmith@example.com")
        assert primary_mail
        self.assertFalse(primary_mail.is_verified)
        self.assertTrue(user.mail_addresses.primary)
        self.assertEqual(stats["mail_count"], 1)

    def test_create_locked_identity(self) -> None:
        user_id = ObjectId("901234567890123456789012")  # johnsmith@example.org / babba-labba
        attributes = {
            "$set": {
                "identities": [{"identity_type": IdentityType.NIN.value, "number": "200102031234", "verified": True}]
            }
        }
        new_attributes = check_locked_identity(self.amdb, user_id, attributes, "test")

        # check_locked_identity should create a locked_identity so add it to the expected attributes
        locked_nin = NinIdentity(number="200102031234", created_by="test", is_verified=True)
        locked_identities = LockedIdentityList(elements=[locked_nin])
        attributes["$set"]["locked_identity"] = locked_identities.to_list_of_dicts()

        self.assertDictEqual(
            normalised_data(attributes, exclude_keys=["created_ts", "modified_ts"]),
            normalised_data(new_attributes, exclude_keys=["created_ts", "modified_ts"]),
        )

    def test_check_locked_identity(self) -> None:
        user_id = ObjectId("012345678901234567890123")  # johnsmith@example.com / hubba-bubba
        user = self.amdb.get_user_by_id(user_id)
        assert user
        locked_nin = NinIdentity(number="197801011234", created_by="test", is_verified=True)

        user.locked_identity.add(locked_nin)
        self.amdb.save(user)
        attributes = {
            "$set": {
                "identities": [
                    {"identity_type": IdentityType.NIN.value, "number": locked_nin.number, "verified": True}
                ],  # hubba-bubba
            }
        }
        new_attributes = check_locked_identity(self.amdb, user_id, attributes, "test")
        # user has locked_identity that is the same as the verified identity so only identities should be set
        self.assertDictEqual(attributes, new_attributes)

    def test_check_locked_identity_wrong_nin(self) -> None:
        user_id = ObjectId("901234567890123456789012")  # johnsmith@example.org / babba-labba
        user = self.amdb.get_user_by_id(user_id)
        assert user
        user.locked_identity.add(NinIdentity(number="200102031234", created_by="test", is_verified=True))
        self.amdb.save(user)
        attributes = {
            "$set": {
                "identities": [{"identity_type": IdentityType.NIN.value, "verified": True, "number": "200506076789"}]
            }
        }
        with self.assertRaises(EduIDUserDBError):
            check_locked_identity(self.amdb, user_id, attributes, "test")

    def test_check_locked_identity_replace_locked(self) -> None:
        user_id = ObjectId("901234567890123456789012")  # johnsmith@example.org / babba-labba
        user = self.amdb.get_user_by_id(user_id)
        assert user
        user.locked_identity.add(NinIdentity(number="200102031234", created_by="test", is_verified=True))
        self.amdb.save(user)
        attributes = {
            "$set": {
                "identities": [{"identity_type": IdentityType.NIN.value, "verified": True, "number": "200506076789"}]
            }
        }
        new_attributes = check_locked_identity(self.amdb, user_id, attributes, "test", replace_locked=IdentityType.NIN)

        # check_locked_identity should replace locked identity with new identity
        locked_nin = NinIdentity(number="200506076789", created_by="test", is_verified=True)
        locked_identities = LockedIdentityList(elements=[locked_nin])
        attributes["$set"]["locked_identity"] = locked_identities.to_list_of_dicts()

        self.assertDictEqual(
            normalised_data(attributes, exclude_keys=["created_ts", "modified_ts"]),
            normalised_data(new_attributes, exclude_keys=["created_ts", "modified_ts"]),
        )

    def test_check_locked_identity_no_verified_nin(self) -> None:
        user_id = ObjectId("012345678901234567890123")  # johnsmith@example.com / hubba-bubba
        attributes = {"$set": {"phone": [{"verified": True, "number": "+34609609609", "primary": True}]}}
        new_attributes = check_locked_identity(self.amdb, user_id, attributes, "test")
        self.assertDictEqual(attributes, new_attributes)

        attributes = {
            "$set": {
                "identities": [{"identity_type": IdentityType.NIN.value, "verified": False, "number": "200506076789"}]
            }
        }
        new_attributes = check_locked_identity(self.amdb, user_id, attributes, "test")
        self.assertDictEqual(attributes, new_attributes)
