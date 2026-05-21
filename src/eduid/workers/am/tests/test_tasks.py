import pytest
from bson import ObjectId

import eduid.userdb
from eduid.common.testing_base import normalised_data
from eduid.userdb import EIDASIdentity, LockedIdentityList, NinIdentity
from eduid.userdb.exceptions import EduIDUserDBError, MultipleUsersReturned
from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.identity import (
    EIDASLoa,
    FrejaIdentity,
    FrejaLoaLevel,
    FrejaRegistrationLevel,
    IdentityType,
    PridPersistence,
    SvipeIdentity,
)
from eduid.userdb.user import User
from eduid.workers.am.consistency_checks import check_locked_identity, unverify_duplicates
from eduid.workers.am.testing import AMTestCase


class TestTasks(AMTestCase):
    user: User

    @pytest.fixture(autouse=True)
    def setup(self, setup_am: None) -> None:
        _users = UserFixtures()
        self.user = _users.mocked_user_standard
        self.amdb.save(self.user)
        self.amdb.save(_users.mocked_user_standard_2)

    def test_get_user_by_id(self) -> None:
        user = self.amdb.get_user_by_id(self.user.user_id)
        assert user
        assert user.mail_addresses.primary
        assert self.user.mail_addresses.primary
        assert user.mail_addresses.primary.email == self.user.mail_addresses.primary.email
        assert not self.amdb.get_user_by_id("123456789012")

    def test_get_user_by_mail(self) -> None:
        assert self.user.mail_addresses.primary
        user = self.amdb.get_user_by_mail(self.user.mail_addresses.primary.email)
        assert user
        assert user.user_id == self.user.user_id

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
        with pytest.raises(MultipleUsersReturned):
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
        assert user.mail_addresses.primary.email != "johnsmith@example.com"
        primary_mail = user.mail_addresses.find("johnsmith@example.com")
        assert primary_mail
        assert not primary_mail.is_verified
        assert user.mail_addresses.primary
        assert stats["mail_count"] == 1

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
        assert user.phone_numbers.primary.number != "+34609609609"
        primary_phone = user.phone_numbers.find("+34609609609")
        assert primary_phone
        assert not primary_phone.is_verified
        assert user.phone_numbers.primary
        assert stats["phone_count"] == 1

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
        assert stats["nin_count"] == 1

    def test_unverify_duplicate_eidas(self) -> None:
        # Add a verified eidas identity to hubba-bubba
        user = self.amdb.get_user_by_eppn("hubba-bubba")
        assert user
        eidas_identity = EIDASIdentity(
            prid="unique/prid/string/1",
            prid_persistence=PridPersistence.B,
            loa=EIDASLoa.NF_SUBSTANTIAL,
            date_of_birth="1978-09-02T00:00:00",
            country_code="DE",
            created_by="test",
            is_verified=True,
            verified_by="test",
        )
        user.identities.add(eidas_identity)
        self.amdb.save(user)

        user_id = ObjectId("901234567890123456789012")  # johnsmith@example.org / babba-labba
        attributes = {
            "$set": {
                "identities": [
                    {
                        "identity_type": IdentityType.EIDAS.value,
                        "prid": "unique/prid/string/1",
                        "prid_persistence": PridPersistence.B.value,
                        "loa": EIDASLoa.NF_SUBSTANTIAL.value,
                        "date_of_birth": "1978-09-02T00:00:00",
                        "country_code": "DE",
                        "verified": True,
                    }
                ]
            }
        }
        stats = unverify_duplicates(self.amdb, user_id, attributes)
        user = self.amdb.get_user_by_eppn("hubba-bubba")
        assert user.identities.eidas is not None
        assert user.identities.eidas.prid == "unique/prid/string/1"
        assert user.identities.eidas.is_verified is False
        assert stats["nin_count"] == 1

    def test_unverify_duplicate_freja(self) -> None:
        # Add a verified freja identity to hubba-bubba
        user = self.amdb.get_user_by_eppn("hubba-bubba")
        assert user
        freja_identity = FrejaIdentity(
            user_id="freja-user-id-1",
            registration_level=FrejaRegistrationLevel.PLUS,
            loa_level=FrejaLoaLevel.LOA3,
            date_of_birth="1978-09-02T00:00:00",
            country_code="SE",
            created_by="test",
            is_verified=True,
            verified_by="test",
        )
        user.identities.add(freja_identity)
        self.amdb.save(user)

        user_id = ObjectId("901234567890123456789012")  # johnsmith@example.org / babba-labba
        attributes = {
            "$set": {
                "identities": [
                    {
                        "identity_type": IdentityType.FREJA.value,
                        "user_id": "freja-user-id-1",
                        "registration_level": FrejaRegistrationLevel.PLUS.value,
                        "loa_level": FrejaLoaLevel.LOA3.value,
                        "date_of_birth": "1978-09-02T00:00:00",
                        "country_code": "SE",
                        "verified": True,
                    }
                ]
            }
        }
        stats = unverify_duplicates(self.amdb, user_id, attributes)
        user = self.amdb.get_user_by_eppn("hubba-bubba")
        assert user.identities.freja is not None
        assert user.identities.freja.user_id == "freja-user-id-1"
        assert user.identities.freja.is_verified is False
        assert stats["nin_count"] == 1

    def test_unverify_duplicate_svipe(self) -> None:
        # Add a verified svipe identity to hubba-bubba
        user = self.amdb.get_user_by_eppn("hubba-bubba")
        assert user
        svipe_identity = SvipeIdentity(
            svipe_id="unique-svipe-id-1",
            administrative_number="1234567890",
            date_of_birth="1978-09-02T00:00:00",
            country_code="DE",
            created_by="test",
            is_verified=True,
            verified_by="test",
        )
        user.identities.add(svipe_identity)
        self.amdb.save(user)

        user_id = ObjectId("901234567890123456789012")  # johnsmith@example.org / babba-labba
        attributes = {
            "$set": {
                "identities": [
                    {
                        "identity_type": IdentityType.SVIPE.value,
                        "svipe_id": "unique-svipe-id-1",
                        "administrative_number": "1234567890",
                        "date_of_birth": "1978-09-02T00:00:00",
                        "country_code": "DE",
                        "verified": True,
                    }
                ]
            }
        }
        stats = unverify_duplicates(self.amdb, user_id, attributes)
        user = self.amdb.get_user_by_eppn("hubba-bubba")
        assert user.identities.svipe is not None
        assert user.identities.svipe.svipe_id == "unique-svipe-id-1"
        assert user.identities.svipe.is_verified is False
        assert stats["nin_count"] == 1

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

        assert user.mail_addresses.primary.email != "johnsmith@example.com"
        primary_mail = user.mail_addresses.find("johnsmith@example.com")
        assert primary_mail
        assert not primary_mail.is_verified
        assert user.mail_addresses.primary

        assert user.phone_numbers.primary
        assert user.phone_numbers.primary.number != "+34609609609"
        primary_phone = user.phone_numbers.find("+34609609609")
        assert primary_phone
        assert not primary_phone.is_verified
        assert user.phone_numbers.primary

        assert user.identities.nin is not None
        assert user.identities.nin.number == "197801011234"
        assert user.identities.nin.is_verified is False

        assert stats["mail_count"] == 1
        assert stats["phone_count"] == 1
        assert stats["nin_count"] == 1

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
        assert user.mail_addresses.primary.email != "johnsmith@example.com"
        primary_mail = user.mail_addresses.find("johnsmith@example.com")
        assert primary_mail
        assert not primary_mail.is_verified
        assert user.mail_addresses.primary
        assert stats["mail_count"] == 1

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

        assert normalised_data(attributes, exclude_keys=["created_ts", "modified_ts"]) == normalised_data(
            new_attributes, exclude_keys=["created_ts", "modified_ts"]
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
        assert attributes == new_attributes

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
        with pytest.raises(EduIDUserDBError):
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

        assert normalised_data(attributes, exclude_keys=["created_ts", "modified_ts"]) == normalised_data(
            new_attributes, exclude_keys=["created_ts", "modified_ts"]
        )

    def test_check_locked_identity_no_verified_nin(self) -> None:
        user_id = ObjectId("012345678901234567890123")  # johnsmith@example.com / hubba-bubba
        attributes = {"$set": {"phone": [{"verified": True, "number": "+34609609609", "primary": True}]}}
        new_attributes = check_locked_identity(self.amdb, user_id, attributes, "test")
        assert attributes == new_attributes

        attributes = {
            "$set": {
                "identities": [{"identity_type": IdentityType.NIN.value, "verified": False, "number": "200506076789"}]
            }
        }
        new_attributes = check_locked_identity(self.amdb, user_id, attributes, "test")
        assert attributes == new_attributes
