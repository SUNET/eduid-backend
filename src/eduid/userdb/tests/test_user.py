import unittest
from datetime import datetime
from hashlib import sha256

import pytest
from bson import ObjectId
from pydantic import ValidationError

from eduid.common.misc.timeutil import utc_now
from eduid.userdb import NinIdentity, OidcAuthorization, OidcIdToken, Orcid
from eduid.userdb.credentials import U2F, CredentialList, CredentialProofingMethod, Password
from eduid.userdb.db.base import TUserDbDocument
from eduid.userdb.exceptions import EduIDUserDBError, UserHasNotCompletedSignup, UserIsRevoked
from eduid.userdb.fixtures.identity import verified_nin_identity
from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.identity import IdentityList, IdentityType
from eduid.userdb.mail import MailAddress, MailAddressList
from eduid.userdb.phone import PhoneNumber, PhoneNumberList
from eduid.userdb.profile import Profile, ProfileList
from eduid.userdb.tou import ToUList
from eduid.userdb.user import SubjectType, User

__author__ = "ft"


def _keyid(kh: str) -> str:
    return "sha256:" + sha256(kh.encode("utf-8")).hexdigest()


class TestNewUser(unittest.TestCase):
    def setUp(self) -> None:
        self.data1 = TUserDbDocument(
            {
                "_id": ObjectId("547357c3d00690878ae9b620"),
                "eduPersonPrincipalName": "guvat-nalif",
                "givenName": "User",
                "chosen_given_name": "User",
                "legal_name": "User One",
                "mail": "user@example.net",
                "mailAliases": [
                    {
                        "added_timestamp": datetime.fromisoformat("2014-12-18T11:25:19.804000"),
                        "email": "user@example.net",
                        "verified": True,
                        "primary": True,
                    }
                ],
                "passwords": [
                    {
                        "created_ts": datetime.fromisoformat("2014-11-24T16:22:49.188000"),
                        "credential_id": "54735b588a7d2a2c4ec3e7d0",
                        "salt": "$NDNv1H1$315d7$32$32$",
                        "created_by": "dashboard",
                        "is_generated": False,
                    }
                ],
                "identities": [verified_nin_identity.to_dict()],
                "subject": "physical person",
                "surname": "One",
                "eduPersonEntitlement": ["http://foo.example.org"],
                "preferredLanguage": "en",
            }
        )

        self.data2 = TUserDbDocument(
            {
                "_id": ObjectId("549190b5d00690878ae9b622"),
                "displayName": "Some \xf6ne",
                "eduPersonPrincipalName": "birub-gagoz",
                "givenName": "Some",
                "mail": "some.one@gmail.com",
                "mailAliases": [
                    {"email": "someone+test1@gmail.com", "verified": True},
                    {
                        "added_timestamp": datetime.fromisoformat("2014-12-17T14:35:14.728000"),
                        "email": "some.one@gmail.com",
                        "verified": True,
                    },
                ],
                "phone": [
                    {
                        "created_ts": datetime.fromisoformat("2014-12-18T09:11:35.078000"),
                        "number": "+46702222222",
                        "primary": True,
                        "verified": True,
                    }
                ],
                "passwords": [
                    {
                        "created_ts": datetime.fromisoformat("2015-02-11T13:58:42.327000"),
                        "id": ObjectId("54db60128a7d2a26e8690cda"),
                        "salt": "$NDNv1H1$db011fc$32$32$",
                        "is_generated": False,
                        "source": "dashboard",
                    },
                    {
                        "version": "U2F_V2",
                        "app_id": "unit test",
                        "keyhandle": "U2F SWAMID AL3",
                        "public_key": "foo",
                        "verified": True,
                        "proofing_method": CredentialProofingMethod.SWAMID_AL3_MFA,
                        "proofing_version": "testing",
                    },
                ],
                "profiles": [
                    {
                        "created_by": "test application",
                        "created_ts": datetime.fromisoformat("2020-02-04T17:42:33.696751"),
                        "owner": "test owner 1",
                        "schema": "test schema",
                        "profile_data": {
                            "a_string": "I am a string",
                            "an_int": 3,
                            "a_list": ["eins", 2, "drei"],
                            "a_map": {"some": "data"},
                        },
                    }
                ],
                "preferredLanguage": "sv",
                "surname": "\xf6ne",
                "subject": "physical person",
            }
        )

        self._setup_user1()
        self._setup_user2()

    def _setup_user1(self) -> None:
        mailAliases_list = [
            MailAddress(
                created_ts=datetime.fromisoformat("2014-12-18T11:25:19.804000"),
                email="user@example.net",
                is_verified=True,
                is_primary=True,
            )
        ]
        password_list = [
            Password(
                created_ts=datetime.fromisoformat("2014-11-24T16:22:49.188000"),
                credential_id="54735b588a7d2a2c4ec3e7d0",
                salt="$NDNv1H1$315d7$32$32$",
                created_by="dashboard",
                is_generated=False,
            )
        ]

        identity_list = [
            NinIdentity(
                number="197801012345",
                created_ts=datetime.fromisoformat("2014-11-24T16:22:49.188000"),
                is_verified=True,
                created_by="dashboard",
            )
        ]
        self.user1 = User(
            user_id=ObjectId("547357c3d00690878ae9b620"),
            eppn="guvat-nalif",
            given_name="User",
            chosen_given_name="User",
            mail_addresses=MailAddressList(elements=mailAliases_list),
            credentials=CredentialList(elements=password_list),
            identities=IdentityList(elements=identity_list),
            legal_name="User One",
            subject=SubjectType("physical person"),
            surname="One",
            entitlements=["http://foo.example.org"],
            language="en",
        )

    def _setup_user2(self) -> None:
        mailAliases_list = [
            MailAddress(email="someone+test1@gmail.com", is_verified=True),
            MailAddress(
                email="some.one@gmail.com",
                created_ts=datetime.fromisoformat("2014-12-17T14:35:14.728000"),
                is_verified=True,
                is_primary=True,
            ),
        ]
        phone_list = [
            PhoneNumber(
                number="+46702222222",
                created_ts=datetime.fromisoformat("2014-12-18T09:11:35.078000"),
                is_primary=True,
                is_verified=True,
            )
        ]
        credential_list = [
            Password(
                created_ts=datetime.fromisoformat("2015-02-11T13:58:42.327000"),
                credential_id="54db60128a7d2a26e8690cda",
                salt="$NDNv1H1$db011fc$32$32$",
                is_generated=False,
                created_by="dashboard",
            ),
            U2F(
                version="U2F_V2",
                app_id="unit test",
                keyhandle="U2F SWAMID AL3",
                public_key="foo",
                is_verified=True,
                proofing_method=CredentialProofingMethod.SWAMID_AL3_MFA,
                proofing_version="testing",
            ),
        ]
        profile = Profile(
            created_by="test application",
            created_ts=datetime.fromisoformat("2020-02-04T17:42:33.696751"),
            owner="test owner 1",
            profile_schema="test schema",
            profile_data={
                "a_string": "I am a string",
                "an_int": 3,
                "a_list": ["eins", 2, "drei"],
                "a_map": {"some": "data"},
            },
        )

        self.user2 = User(
            user_id=ObjectId("549190b5d00690878ae9b622"),
            eppn="birub-gagoz",
            given_name="Some",
            mail_addresses=MailAddressList(elements=mailAliases_list),
            phone_numbers=PhoneNumberList(elements=phone_list),
            credentials=CredentialList(elements=credential_list),
            profiles=ProfileList(elements=[profile]),
            language="sv",
            surname="\xf6ne",
            subject=SubjectType("physical person"),
        )

    def test_user_id(self) -> None:
        self.assertEqual(self.user1.user_id, self.data1["_id"])

    def test_eppn(self) -> None:
        self.assertEqual(self.user1.eppn, self.data1["eduPersonPrincipalName"])

    def test_given_name(self) -> None:
        self.assertEqual(self.user2.given_name, self.data2["givenName"])

    def test_chosen_given_name(self) -> None:
        self.assertEqual(self.user1.chosen_given_name, self.data1["chosen_given_name"])

    def test_surname(self) -> None:
        self.assertEqual(self.user2.surname, self.data2["surname"])

    def test_legal_name(self) -> None:
        self.assertEqual(self.user1.legal_name, self.data1["legal_name"])

    def test_mail_addresses(self) -> None:
        assert self.user1.mail_addresses.primary is not None
        self.assertEqual(self.user1.mail_addresses.primary.email, self.data1["mailAliases"][0]["email"])

    def test_passwords(self) -> None:
        """
        Test that we get back a dict identical to the one we put in for old-style userdb data.
        """
        expected = self.data1["passwords"]
        obtained = self.user1.credentials.to_list_of_dicts()

        # modified_ts is added when not present, verify it is current
        modified_ts = obtained[0].pop("modified_ts")
        now = utc_now()
        assert (now - modified_ts).total_seconds() < 2

        assert obtained == expected

    def test_unknown_attributes(self) -> None:
        """
        Test parsing a document with unknown data in it.
        """
        data = self.data1
        data["unknown_attribute"] = "something"

        with self.assertRaises(ValidationError):
            User.from_dict(data)

    def test_incomplete_signup_user(self) -> None:
        """
        Test parsing the incomplete documents left in the central userdb by older Signup application.
        """
        data = TUserDbDocument(
            {
                "_id": ObjectId(),
                "eduPersonPrincipalName": "vohon-mufus",
                "mail": "olle@example.org",
                "mailAliases": [{"email": "olle@example.org", "verified": False}],
            }
        )
        with self.assertRaises(UserHasNotCompletedSignup):
            User.from_dict(data)
        data["subject"] = "physical person"  # later signup added this attribute
        with self.assertRaises(UserHasNotCompletedSignup):
            User.from_dict(data)
        data["mailAliases"][0]["verified"] = True
        data["surname"] = "not signup-incomplete anymore"
        data["passwords"] = [
            {
                "created_ts": datetime.fromisoformat("2014-09-04T08:57:07.362000"),
                "credential_id": str(ObjectId()),
                "salt": "salt",
                "created_by": "dashboard",
                "is_generated": False,
            }
        ]
        user = User.from_dict(data)
        self.assertEqual(user.surname, data["surname"])

        expected = data["passwords"]
        obtained = user.credentials.to_list_of_dicts()

        assert obtained == expected

    def test_revoked_user(self) -> None:
        """
        Test ability to identify revoked users.
        """
        data = TUserDbDocument(
            {
                "_id": ObjectId(),
                "eduPersonPrincipalName": "binib-mufus",
                "revoked_ts": datetime.fromisoformat("2015-05-26T08:33:56.826000"),
                "passwords": [],
            }
        )
        with self.assertRaises(UserIsRevoked):
            User.from_dict(data)

    def test_user_with_no_primary_mail(self) -> None:
        mail = "yahoo@example.com"
        data = TUserDbDocument(
            {
                "_id": ObjectId(),
                "eduPersonPrincipalName": "lutol-bafim",
                "mailAliases": [{"email": mail, "verified": True}],
                "passwords": [
                    {
                        "created_ts": datetime.fromisoformat("2014-09-04T08:57:07.362000"),
                        "credential_id": str(ObjectId()),
                        "salt": "salt",
                        "source": "dashboard",
                    }
                ],
            }
        )
        user = User.from_dict(data)
        assert user.mail_addresses.primary
        self.assertEqual(mail, user.mail_addresses.primary.email)

    def test_user_with_indirectly_verified_primary_mail(self) -> None:
        """
        If a user has passwords set, the 'mail' attribute will be considered indirectly verified.
        """
        mail = "yahoo@example.com"
        data = TUserDbDocument(
            {
                "_id": ObjectId(),
                "eduPersonPrincipalName": "lutol-bafim",
                "mail": mail,
                "mailAliases": [{"email": mail, "verified": False}],
                "passwords": [
                    {
                        "created_ts": datetime.fromisoformat("2014-09-04T08:57:07.362000"),
                        "credential_id": str(ObjectId()),
                        "salt": "salt",
                        "source": "dashboard",
                    }
                ],
            }
        )
        user = User.from_dict(data)
        assert user.mail_addresses.primary
        self.assertEqual(mail, user.mail_addresses.primary.email)

    def test_user_with_indirectly_verified_primary_mail_and_explicit_primary_mail(self) -> None:
        """
        If a user has manage to verify a mail address in the new style with the same address still
        set in old style mail property. Do not make old mail address primary if a primary all ready exists.
        """
        old_mail = "yahoo@example.com"
        new_mail = "not_yahoo@example.com"
        data = TUserDbDocument(
            {
                "_id": ObjectId(),
                "eduPersonPrincipalName": "lutol-bafim",
                "mail": old_mail,
                "mailAliases": [
                    {"email": old_mail, "verified": True, "primary": False},
                    {"email": new_mail, "verified": True, "primary": True},
                ],
                "passwords": [
                    {
                        "created_ts": datetime.fromisoformat("2014-09-04T08:57:07.362000"),
                        "credential_id": str(ObjectId()),
                        "salt": "salt",
                        "source": "dashboard",
                    }
                ],
            }
        )
        user = User.from_dict(data)
        assert user.mail_addresses.primary
        self.assertEqual(new_mail, user.mail_addresses.primary.email)

    def test_user_with_csrf_junk_in_mail_address(self) -> None:
        """
        For a long time, Dashboard leaked CSRF tokens into the mail address dicts.
        """
        mail = "yahoo@example.com"
        data = TUserDbDocument(
            {
                "_id": ObjectId(),
                "eduPersonPrincipalName": "test-test",
                "mailAliases": [{"email": mail, "verified": True, "csrf": "6ae1d4e95305b72318a683883e70e3b8e302cd75"}],
                "passwords": [
                    {
                        "created_ts": datetime.fromisoformat("2014-09-04T08:57:07.362000"),
                        "credential_id": str(ObjectId()),
                        "salt": "salt",
                        "source": "dashboard",
                    }
                ],
            }
        )
        user = User.from_dict(data)
        assert user.mail_addresses.primary
        self.assertEqual(mail, user.mail_addresses.primary.email)

    def test_to_dict(self) -> None:
        """
        Test that User objects can be recreated.
        """
        d1 = self.user1.to_dict()
        u2 = User.from_dict(d1)
        d2 = u2.to_dict()
        self.assertEqual(d1, d2)

    def test_modified_ts(self) -> None:
        """
        Test the modified_ts property.
        """
        _time1 = self.user1.modified_ts
        assert _time1 is None
        # update to current time
        self.user1.modified_ts = utc_now()
        _time2 = self.user1.modified_ts
        self.assertNotEqual(_time1, _time2)
        # set to a datetime instance
        self.user1.modified_ts = utc_now()
        self.assertNotEqual(_time2, self.user1.modified_ts)

    def test_two_unverified_non_primary_phones(self) -> None:
        """
        Test that the first entry in the `phone' list is chosen as primary when none are verified.
        """
        number1 = "+9112345678"
        number2 = "+9123456789"
        data = TUserDbDocument(
            {
                "_id": ObjectId(),
                "displayName": "xxx yyy",
                "eduPersonPrincipalName": "pohig-test",
                "givenName": "xxx",
                "mail": "test@gmail.com",
                "mailAliases": [{"email": "test@gmail.com", "verified": True}],
                "phone": [
                    {
                        "csrf": "47d42078719b8377db622c3ff85b94840b483c92",
                        "number": number1,
                        "primary": False,
                        "verified": False,
                    },
                    {
                        "csrf": "47d42078719b8377db622c3ff85b94840b483c92",
                        "number": number2,
                        "primary": False,
                        "verified": False,
                    },
                ],
                "passwords": [
                    {
                        "created_ts": datetime.fromisoformat("2014-06-29T17:52:37.830000"),
                        "credential_id": str(ObjectId()),
                        "salt": "$NDNv1H1$foo$32$32$",
                        "source": "dashboard",
                    }
                ],
                "preferredLanguage": "en",
                "surname": "yyy",
            }
        )
        user = User.from_dict(data)
        self.assertEqual(user.phone_numbers.primary, None)

    def test_two_non_primary_phones(self) -> None:
        """
        Test that the first verified number is chosen as primary, if there is a verified number.
        """
        number1 = "+9112345678"
        number2 = "+9123456789"
        data = TUserDbDocument(
            {
                "_id": ObjectId(),
                "displayName": "xxx yyy",
                "eduPersonPrincipalName": "pohig-test",
                "givenName": "xxx",
                "mail": "test@gmail.com",
                "mailAliases": [{"email": "test@gmail.com", "verified": True}],
                "phone": [
                    {
                        "csrf": "47d42078719b8377db622c3ff85b94840b483c92",
                        "number": number1,
                        "primary": False,
                        "verified": False,
                    },
                    {
                        "csrf": "47d42078719b8377db622c3ff85b94840b483c92",
                        "number": number2,
                        "primary": False,
                        "verified": True,
                    },
                ],
                "passwords": [
                    {
                        "created_ts": datetime.fromisoformat("2014-06-29T17:52:37.830000"),
                        "credential_id": str(ObjectId()),
                        "salt": "$NDNv1H1$foo$32$32$",
                        "source": "dashboard",
                    }
                ],
                "preferredLanguage": "en",
                "surname": "yyy",
            }
        )
        user = User.from_dict(data)
        assert user.phone_numbers.primary
        self.assertEqual(user.phone_numbers.primary.number, number2)

    def test_primary_non_verified_phone(self) -> None:
        """
        Test that if a non verified phone number is primary, due to earlier error, then that primary flag is removed.
        """
        data = TUserDbDocument(
            {
                "_id": ObjectId(),
                "displayName": "xxx yyy",
                "eduPersonPrincipalName": "pohig-test",
                "givenName": "xxx",
                "mail": "test@gmail.com",
                "mailAliases": [{"email": "test@gmail.com", "verified": True}],
                "phone": [
                    {
                        "csrf": "47d42078719b8377db622c3ff85b94840b483c92",
                        "number": "+9112345678",
                        "primary": True,
                        "verified": False,
                    }
                ],
                "passwords": [
                    {
                        "created_ts": datetime.fromisoformat("2014-06-29T17:52:37.830000"),
                        "credential_id": str(ObjectId()),
                        "salt": "$NDNv1H1$foo$32$32$",
                        "source": "dashboard",
                    }
                ],
                "preferredLanguage": "en",
                "surname": "yyy",
            }
        )
        user = User.from_dict(data)
        for number in user.phone_numbers.to_list():
            self.assertEqual(number.is_primary, False)

    def test_primary_non_verified_phone2(self) -> None:
        """
        Test that if a non verified phone number is primary, due to earlier error, then that primary flag is removed.
        """
        data = TUserDbDocument(
            {
                "_id": ObjectId(),
                "eduPersonPrincipalName": "pohig-test",
                "mail": "test@gmail.com",
                "mailAliases": [{"email": "test@gmail.com", "verified": True}],
                "phone": [
                    {"number": "+11111111111", "primary": True, "verified": False},
                    {"number": "+22222222222", "primary": False, "verified": True},
                ],
                "passwords": [
                    {
                        "created_ts": datetime.fromisoformat("2014-06-29T17:52:37.830000"),
                        "id": ObjectId(),
                        "salt": "$NDNv1H1$foo$32$32$",
                        "source": "dashboard",
                    }
                ],
            }
        )
        user = User.from_dict(data)
        assert user.phone_numbers.primary
        self.assertEqual(user.phone_numbers.primary.number, "+22222222222")

    def test_user_tou_no_created_ts(self) -> None:
        """
        Basic test for user ToU.
        """
        tou_dict = {
            "event_id": str(ObjectId()),
            "event_type": "tou_event",
            "version": "1",
            "created_by": "unit test",
        }
        tou_events = ToUList.from_list_of_dicts([tou_dict])
        data = self.data1
        data.update({"tou": tou_events.to_list_of_dicts()})
        user = User.from_dict(data)
        # If we create the ToU from a dict w/o created_ts key, the created object will carry a _no_created_ts_in_db
        # attr set to True, and therefore the to_dict method will wipe out the created_ts key
        self.assertFalse(user.tou.has_accepted("1", reaccept_interval=94608000))  # reaccept_interval seconds (3 years)

    def test_user_tou(self) -> None:
        """
        Basic test for user ToU.
        """
        tou_dict = {
            "event_id": str(ObjectId()),
            "event_type": "tou_event",
            "version": "1",
            "created_by": "unit test",
            "created_ts": utc_now(),
        }
        tou_events = ToUList.from_list_of_dicts([tou_dict])
        data = self.data1
        data.update({"tou": tou_events.to_list_of_dicts()})
        user = User.from_dict(data)
        self.assertTrue(user.tou.has_accepted("1", reaccept_interval=94608000))  # reaccept_interval seconds (3 years)
        self.assertFalse(user.tou.has_accepted("2", reaccept_interval=94608000))  # reaccept_interval seconds (3 years)

    def test_locked_identity_load(self) -> None:
        created_ts = datetime.fromisoformat("2013-09-02T10:23:25")
        locked_identity = {
            "created_by": "test",
            "identity_type": IdentityType.NIN.value,
            "number": "197801012345",
            "verified": True,
            "created_ts": str(created_ts),
        }
        data = self.data1
        data["locked_identity"] = [locked_identity]
        user = User.from_dict(data)
        assert user.locked_identity.nin is not None
        assert user.locked_identity.nin.identity_type == IdentityType.NIN.value
        assert user.locked_identity.nin.created_by == "test"
        assert user.locked_identity.nin.created_ts == created_ts
        assert user.locked_identity.nin.number == "197801012345"
        assert user.locked_identity.nin.is_verified is True

    def test_locked_identity_load_legacy_format(self) -> None:
        created_ts = datetime.fromisoformat("2013-09-02T10:23:25")
        locked_identity = {
            "created_by": "test",
            "identity_type": "nin",
            "number": "197801012345",
            "created_ts": str(created_ts),
        }
        data = self.data1
        data["locked_identity"] = [locked_identity]
        user = User.from_dict(data)
        assert user.locked_identity.nin is not None
        assert user.locked_identity.nin.identity_type == IdentityType.NIN.value
        assert user.locked_identity.nin.created_by == "test"
        assert user.locked_identity.nin.created_ts == created_ts
        assert user.locked_identity.nin.number == "197801012345"
        assert user.locked_identity.nin.is_verified is True

    def test_locked_identity_set(self) -> None:
        user = User.from_dict(self.data1)
        locked_nin = NinIdentity(
            number="197801012345",
            created_by="test",
            is_verified=True,
        )
        user.locked_identity.add(locked_nin)
        self.assertEqual(user.locked_identity.count, 1)

        assert user.locked_identity.nin is not None
        assert user.locked_identity.nin.identity_type == IdentityType.NIN.value
        assert user.locked_identity.nin.created_by == "test"
        assert user.locked_identity.nin.number == "197801012345"
        assert user.locked_identity.nin.is_verified is True

    def test_locked_identity_set_not_verified(self) -> None:
        locked_identity = {"created_by": "test", "identity_type": IdentityType.NIN.value, "number": "197801012345"}
        user = User.from_dict(self.data1)
        locked_nin = NinIdentity(number=locked_identity["number"], created_by=locked_identity["created_by"])
        with pytest.raises(ValidationError):
            user.locked_identity.add(locked_nin)

    def test_locked_identity_to_dict(self) -> None:
        user = User.from_dict(self.data1)
        locked_nin = NinIdentity(
            number="197801012345",
            created_by="test",
            is_verified=True,
        )
        user.locked_identity.add(locked_nin)

        old_user = User.from_dict(user.to_dict())
        assert old_user.locked_identity.nin is not None
        assert old_user.locked_identity.nin.identity_type == IdentityType.NIN.value
        assert old_user.locked_identity.nin.created_by == "test"
        assert old_user.locked_identity.nin.number == "197801012345"
        assert old_user.locked_identity.nin.is_verified is True

        new_user = User.from_dict(user.to_dict())
        assert new_user.locked_identity.nin is not None
        assert new_user.locked_identity.nin.identity_type == IdentityType.NIN.value
        assert new_user.locked_identity.nin.created_by == "test"
        assert new_user.locked_identity.nin.number == "197801012345"
        assert new_user.locked_identity.nin.is_verified is True

    def test_locked_identity_remove(self) -> None:
        user = User.from_dict(self.data1)
        locked_nin = NinIdentity(
            number="197801012345",
            created_by="test",
            is_verified=True,
        )
        user.locked_identity.add(locked_nin)
        with self.assertRaises(EduIDUserDBError):
            user.locked_identity.remove(locked_nin.key)

    def test_orcid(self) -> None:
        id_token = {
            "aud": ["APP_ID"],
            "auth_time": 1526389879,
            "exp": 1526392540,
            "iat": 1526391940,
            "iss": "https://op.example.org",
            "sub": "subject_identifier",
            "nonce": "a_nonce_token",
        }
        oidc_data = {
            "access_token": "b8b8ca5d-b233-4d49-830a-ede934c626d3",
            "expires_in": 631138518,
            "refresh_token": "a110e7d2-4968-42d4-a91d-f379b55a0e60",
            "token_type": "bearer",
        }
        orcid = "user_orcid"
        id_token["created_by"] = "test"
        oidc_id_token = OidcIdToken.from_dict(id_token)
        oidc_data["created_by"] = "test"
        oidc_data["id_token"] = oidc_id_token
        oidc_authz = OidcAuthorization.from_dict(oidc_data)
        orcid_element = Orcid.from_dict({"id": orcid, "oidc_authz": oidc_authz, "created_by": "test"})

        user = User.from_dict(self.data1)
        user.orcid = orcid_element

        old_user = User.from_dict(user.to_dict())
        assert old_user
        assert old_user.orcid
        self.assertIsInstance(old_user.orcid.created_by, str)
        self.assertIsInstance(old_user.orcid.created_ts, datetime)
        self.assertIsInstance(old_user.orcid.id, str)
        self.assertIsInstance(old_user.orcid.oidc_authz, OidcAuthorization)
        self.assertIsInstance(old_user.orcid.oidc_authz.id_token, OidcIdToken)

        new_user = User.from_dict(user.to_dict())
        assert new_user
        assert new_user.orcid
        self.assertIsInstance(new_user.orcid.created_by, str)
        self.assertIsInstance(new_user.orcid.created_ts, datetime)
        self.assertIsInstance(new_user.orcid.id, str)
        self.assertIsInstance(new_user.orcid.oidc_authz, OidcAuthorization)
        self.assertIsInstance(new_user.orcid.oidc_authz.id_token, OidcIdToken)

    def test_profiles(self) -> None:
        self.assertIsNotNone(self.user1.profiles)
        self.assertEqual(self.user1.profiles.count, 0)
        self.assertIsNotNone(self.user2.profiles)
        self.assertEqual(self.user2.profiles.count, 1)

    def test_user_verified_credentials(self) -> None:
        ver = [x for x in self.user2.credentials.to_list() if x.is_verified]
        keys = [x.key for x in ver]
        self.assertEqual(keys, [_keyid("U2F SWAMID AL3" + "foo")])

    def test_user_unverified_credential(self) -> None:
        cred = next(x for x in self.user2.credentials.to_list() if x.is_verified)
        self.assertEqual(cred.proofing_method, CredentialProofingMethod.SWAMID_AL3_MFA)
        _dict1 = cred.to_dict()
        self.assertEqual(_dict1["verified"], True)
        self.assertEqual(_dict1["proofing_method"], CredentialProofingMethod.SWAMID_AL3_MFA)
        self.assertEqual(_dict1["proofing_version"], "testing")
        cred.is_verified = False
        _dict2 = cred.to_dict()
        self.assertFalse("verified" in _dict2)
        self.assertFalse("proofing_method" in _dict2)
        self.assertFalse("proofing_version" in _dict2)

    def test_both_mobile_and_phone(self) -> None:
        """Test user that has both 'mobile' and 'phone'"""
        phone = [
            {"number": "+4673123", "primary": True, "verified": True},
            {"created_by": "phone", "number": "+4670999", "primary": False, "verified": False},
        ]
        user = User.from_dict(
            data=TUserDbDocument(
                {
                    "_id": ObjectId(),
                    "eduPersonPrincipalName": "test-test",
                    "passwords": [],
                    "mobile": [{"mobile": "+4673123", "primary": True, "verified": True}],
                    "phone": phone,
                }
            )
        )
        out = user.to_dict()["phone"]

        assert phone == out, "The phone objects differ when using both phone and mobile"

    def test_both_sn_and_surname(self) -> None:
        """Test user that has both 'sn' and 'surname'"""
        user = User.from_dict(
            data=TUserDbDocument(
                {
                    "_id": ObjectId(),
                    "eduPersonPrincipalName": "test-test",
                    "passwords": [],
                    "surname": "Right",
                    "sn": "Wrong",
                }
            )
        )
        self.assertEqual("Right", user.to_dict()["surname"])

    def test_terminated_user(self) -> None:
        data = self.user1.to_dict()
        data["terminated"] = utc_now()
        user = User.from_dict(data)
        assert user.terminated is not None
        assert isinstance(user.terminated, datetime) is True

    def test_terminated_user_false(self) -> None:
        # users can have terminated set to False due to a bug in the past
        data = self.user1.to_dict()
        data["terminated"] = False
        user = User.from_dict(data)
        assert user.terminated is None

    def test_rebuild_user1(self) -> None:
        data = self.user1.to_dict()
        new_user1 = User.from_dict(data)
        self.assertEqual(new_user1.eppn, "guvat-nalif")

    def test_rebuild_user2(self) -> None:
        data = self.user2.to_dict()
        new_user2 = User.from_dict(data)
        self.assertEqual(new_user2.eppn, "birub-gagoz")

    def test_mail_addresses_from_dict(self) -> None:
        """
        Test that we get back a correct list of dicts for old-style userdb data.
        """
        mailAliases_list = [
            {"email": "someone+test1@gmail.com", "verified": True},
            {
                "created_ts": datetime.fromisoformat("2014-12-17T14:35:14.728000"),
                "email": "some.one@gmail.com",
                "verified": True,
                "primary": True,
            },
        ]
        mail_addresses = MailAddressList.from_list_of_dicts(mailAliases_list)

        to_dict_output = mail_addresses.to_list_of_dicts()

        # The {'email': 'someone+test1@gmail.com', 'verified': True} should've beem flagged as primary: False
        found = False
        for this in to_dict_output:
            if this["email"] == "someone+test1@gmail.com":
                assert this["primary"] is False
                # now delete the marking from the to_list_of_dicts output to be able to compare it to the input below
                del this["primary"]
                found = True
        assert found is True, "The non-primary e-mail in the input dict was not marked as non-primary"

        assert to_dict_output == mailAliases_list

    def test_phone_numbers_from_dict(self) -> None:
        """
        Test that we get back a dict identical to the one we put in for old-style userdb data.
        """
        phone_list = [
            {
                "created_ts": datetime.fromisoformat("2014-12-18T09:11:35.078000"),
                "number": "+46702222222",
                "primary": True,
                "verified": True,
            }
        ]
        phone_numbers = PhoneNumberList.from_list_of_dicts(phone_list)
        to_dict_result = phone_numbers.to_list_of_dicts()
        assert to_dict_result == phone_list

    def test_passwords_from_dict(self) -> None:
        """
        Test that we get back a dict identical to the one we put in for old-style userdb data.
        """
        first = {
            "created_ts": datetime.fromisoformat("2015-02-11T13:58:42.327000"),
            "id": ObjectId("54db60128a7d2a26e8690cda"),
            "salt": "$NDNv1H1$db011fc$32$32$",
            "is_generated": False,
            "source": "dashboard",
        }
        second = {
            "version": "U2F_V2",
            "app_id": "unit test",
            "keyhandle": "U2F SWAMID AL3",
            "public_key": "foo",
            "verified": True,
            "mfa_approved": False,
            "proofing_method": CredentialProofingMethod.SWAMID_AL3_MFA,
            "proofing_version": "testing",
        }

        password_list = [first, second]
        passwords = CredentialList.from_list_of_dicts(password_list)

        to_dict_result = passwords.to_list_of_dicts()

        # adjust for expected changes
        first["created_by"] = first.pop("source")
        first["credential_id"] = str(first.pop("id"))
        second["description"] = ""

        expected = [first, second]

        assert to_dict_result == expected

    def test_phone_numbers(self) -> None:
        """
        Test that we get back a dict identical to the one we put in for old-style userdb data.
        """
        to_dict_result = self.user2.phone_numbers.to_list_of_dicts()

        expected = self.data2["phone"]
        obtained = to_dict_result

        # modified_ts is added when not present, verify it is current
        modified_ts = obtained[0].pop("modified_ts")
        now = utc_now()
        assert (now - modified_ts).total_seconds() < 2

        assert obtained == expected

    def test_user_meta(self) -> None:
        version = ObjectId()
        _utc_now = utc_now()
        user_dict = self.user1.to_dict()
        user_dict["meta"] = {}
        user_dict["meta"]["version"] = version
        user_dict["meta"]["modified_ts"] = _utc_now
        user_dict["meta"]["created_ts"] = _utc_now
        user = User.from_dict(user_dict)
        assert user.meta.version == version
        assert user.meta.modified_ts == _utc_now
        assert user.meta.created_ts == _utc_now
        user_dict2 = user.to_dict()
        expected = {
            "version": version,
            "modified_ts": _utc_now,
            "created_ts": _utc_now,
        }
        assert user_dict2["meta"] == expected

    def test_user_meta_version(self) -> None:
        assert self.user1.meta.is_in_database is False
        assert self.user1.meta.version is None
        self.user1.meta.new_version()
        assert self.user1.meta.is_in_database is False
        assert isinstance(self.user1.meta.version, ObjectId) is True

    def test_user_meta_modified_ts(self) -> None:
        assert self.user1.meta.modified_ts is None
        # TODO: remove below check when removing user.modified_ts
        # verify that user.modified_ts is synced with meta.modified_ts
        self.user1.modified_ts = utc_now()
        assert self.user1.meta.modified_ts == self.user1.modified_ts

    def test_letter_proofing_data_to_list(self) -> None:
        letter_proofing = {
            "created_by": "eduid-idproofing-letter",
            "created_ts": datetime(2015, 12, 18, 12, 0, 46),
            "number": "198311220134",
            "official_address": {
                "Name": {
                    "GivenName": "Test Testaren",
                    "GivenNameMarking": "10",
                    "MiddleName": "Testare",
                    "Surname": "Testsson",
                },
                "OfficialAddress": {
                    "Address2": "VÄGEN 16",
                    "City": "STADEN",
                    "PostalCode": "12345",
                },
            },
            "transaction_id": "0000000-0000-0000-0000-00000000",
            "verification_code": "xxxxxxxxxx",
            "verified": True,
            "verified_by": "eduid-idproofing-letter",
            "verified_ts": datetime(2015, 12, 18, 12, 3, 20),
        }
        user_dict = UserFixtures().mocked_user_standard.to_dict()
        user_dict["letter_proofing_data"] = letter_proofing
        user = User.from_dict(user_dict)
        assert user.to_dict()["letter_proofing_data"] == [letter_proofing]

    def test_nins_and_identities_on_user(self) -> None:
        user_dict = UserFixtures().mocked_user_standard.to_dict()
        assert user_dict["identities"] != []
        user_dict = User.from_dict(user_dict).to_dict()
        assert user_dict.get("nins") is None
        assert user_dict.get("identities") is not None

    def test_empty_nins_list(self) -> None:
        user_dict = UserFixtures().mocked_user_standard.to_dict()
        del user_dict["identities"]
        user_dict["nins"] = []
        user = User.from_dict(user_dict)
        assert len(user.identities.to_list()) == 0
