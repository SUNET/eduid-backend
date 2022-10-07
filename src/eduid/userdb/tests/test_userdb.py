#
# Copyright (c) 2015 NORDUnet A/S
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

import bson

from eduid.userdb import User
from eduid.userdb.fixtures.passwords import signup_password
from eduid.userdb.fixtures.users import mocked_user_standard, new_user_example
from eduid.userdb.identity import IdentityType
from eduid.userdb.meta import CleanedType
from eduid.userdb.testing import MongoTestCase, normalised_data


class TestUserDB(MongoTestCase):
    def setUp(self, *args, **kwargs):
        self.user = mocked_user_standard
        super().setUp(am_users=[self.user, new_user_example], **kwargs)

    def test_get_user_by_id(self):
        """Test get_user_by_id"""
        res = self.amdb.get_user_by_id(self.user.user_id)
        assert self.user.user_id == res.user_id

        res = self.amdb.get_user_by_id(str(self.user.user_id))
        assert self.user.user_id == res.user_id

        res = self.amdb.get_user_by_id(str(bson.ObjectId()))
        assert res is None

        res = self.amdb.get_user_by_id("not-a-valid-object-id")
        assert res is None

    def test_get_user_by_nin(self):
        """Test get_user_by_nin"""
        test_user = self.amdb.get_user_by_id(self.user.user_id)
        test_user.given_name = "Kalle Anka"
        self.amdb.save(test_user)
        res = self.amdb.get_user_by_nin(test_user.identities.nin.number)
        assert test_user.given_name == res.given_name

    def test_remove_user_by_id(self):
        """Test removing a user from the database

        NOTE: remove_user_by_id() should be moved to SignupUserDb
        """
        test_user = self.amdb.get_user_by_id(self.user.user_id)
        res = self.amdb.get_users_by_nin(test_user.identities.nin.number)
        assert normalised_data(res[0].to_dict()) == normalised_data(test_user.to_dict())
        self.amdb.remove_user_by_id(test_user.user_id)
        res = self.amdb.get_users_by_nin(test_user.identities.nin.number)
        assert res == []

    def test_get_user_by_eppn(self):
        """Test user lookup using eppn"""
        test_user = self.amdb.get_user_by_id(self.user.user_id)
        res = self.amdb.get_user_by_eppn(test_user.eppn)
        assert test_user.user_id == res.user_id

    def test_get_user_by_eppn_not_found(self):
        """Test user lookup using unknown"""
        assert self.amdb.get_user_by_eppn("abc123") is None

    def test_get_uncleaned_users(self):
        docs = self.amdb.get_uncleaned_verified_users(
            cleaned_type=CleanedType.SKV, identity_type=IdentityType.NIN, limit=10
        )
        self.assertEqual(1, len(docs))
        assert len(docs) == 1
        assert docs[0].eppn == "hubba-bubba"


class TestUserDB_mail(MongoTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        data1 = {
            "_id": bson.ObjectId(),
            "eduPersonPrincipalName": "mail-test1",
            "mail": "test@gmail.com",
            "mailAliases": [{"email": "test@gmail.com", "verified": True}],
            "passwords": [signup_password.to_dict()],
        }

        data2 = {
            "_id": bson.ObjectId(),
            "eduPersonPrincipalName": "mail-test2",
            "mailAliases": [
                {"email": "test2@gmail.com", "primary": True, "verified": True},
                {"email": "test@gmail.com", "verified": False},
            ],
            "passwords": [signup_password.to_dict()],
        }

        self.user1 = User.from_dict(data1)
        self.user2 = User.from_dict(data2)

        self.amdb.save(self.user1, check_sync=False)
        self.amdb.save(self.user2, check_sync=False)

    def test_get_user_by_mail(self):
        test_user = self.amdb.get_user_by_id(self.user1.user_id)
        res = self.amdb.get_user_by_mail(test_user.mail_addresses.primary.email)
        assert test_user.user_id == res.user_id

    def test_get_user_by_mail_unknown(self):
        """Test searching for unknown e-mail address"""
        assert self.amdb.get_user_by_mail("abc123@example.edu") is None

    def test_get_user_by_mail_multiple(self):
        res = self.amdb.get_users_by_mail("test@gmail.com")
        ids = [x.user_id for x in res]
        assert ids == [self.user1.user_id]

        res = self.amdb.get_users_by_mail("test@gmail.com", include_unconfirmed=True)
        ids = [x.user_id for x in res]
        assert ids == [self.user1.user_id, self.user2.user_id]


class TestUserDB_phone(MongoTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        data1 = {
            "_id": bson.ObjectId(),
            "eduPersonPrincipalName": "phone-test1",
            "mail": "kalle@example.com",
            "phone": [
                {"number": "+11111111111", "primary": True, "verified": True},
                {"number": "+22222222222", "primary": False, "verified": True},
            ],
            "passwords": [signup_password.to_dict()],
        }
        data2 = {
            "_id": bson.ObjectId(),
            "eduPersonPrincipalName": "phone-test2",
            "mail": "anka@example.com",
            "phone": [
                {"number": "+11111111111", "primary": True, "verified": False},
                {"number": "+22222222222", "primary": False, "verified": False},
                {"number": "+33333333333", "primary": False, "verified": False},
            ],
            "passwords": [signup_password.to_dict()],
        }

        self.user1 = User.from_dict(data1)
        self.user2 = User.from_dict(data2)
        self.amdb.save(self.user1)
        self.amdb.save(self.user2)

    def test_get_user_by_phone(self):
        test_user = self.amdb.get_user_by_id(self.user1.user_id)
        res = self.amdb.get_user_by_phone(test_user.phone_numbers.primary.number)
        assert res.user_id == test_user.user_id

        res = self.amdb.get_user_by_phone("+22222222222")
        assert res.user_id == test_user.user_id

        assert self.amdb.get_user_by_phone("+33333333333") is None

        res = self.amdb.get_users_by_phone("+33333333333", include_unconfirmed=True)
        assert [x.user_id for x in res] == [self.user2.user_id]

    def test_get_user_by_phone_unknown(self):
        """Test searching for unknown e-phone address"""
        assert self.amdb.get_user_by_phone("abc123@example.edu") is None

    def test_get_user_by_phone_multiple(self):
        res = self.amdb.get_users_by_phone("+11111111111")
        ids = [x.user_id for x in res]
        assert ids == [self.user1.user_id]

        res = self.amdb.get_users_by_phone("+11111111111", include_unconfirmed=True)
        ids = [x.user_id for x in res]
        assert ids == [self.user1.user_id, self.user2.user_id]


class TestUserDB_nin(MongoTestCase):
    # TODO: Keep for a while to make sure the conversion to identities work as expected
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        data1 = {
            "_id": bson.ObjectId(),
            "eduPersonPrincipalName": "nin-test1",
            "mail": "kalle@example.com",
            "nins": [
                {"number": "11111111111", "primary": True, "verified": True},
            ],
            "passwords": [signup_password.to_dict()],
        }
        data2 = {
            "_id": bson.ObjectId(),
            "eduPersonPrincipalName": "nin-test2",
            "mail": "anka@example.com",
            "nins": [
                {"number": "22222222222", "primary": True, "verified": True},
            ],
            "passwords": [signup_password.to_dict()],
        }

        data3 = {
            "_id": bson.ObjectId(),
            "eduPersonPrincipalName": "nin-test3",
            "mail": "anka@example.com",
            "nins": [
                {"number": "33333333333", "primary": False, "verified": False},
            ],
            "passwords": [signup_password.to_dict()],
        }

        self.user1 = User.from_dict(data1)
        self.user2 = User.from_dict(data2)
        self.user3 = User.from_dict(data3)

        self.amdb.save(self.user1)
        self.amdb.save(self.user2)
        self.amdb.save(self.user3)

    def test_get_user_by_nin(self):
        test_user = self.amdb.get_user_by_id(self.user1.user_id)
        res = self.amdb.get_user_by_nin(test_user.identities.nin.number)
        assert res.user_id == test_user.user_id, "alpha"

        res = self.amdb.get_user_by_nin("11111111111")
        assert res.user_id == test_user.user_id, "beta"

        res = self.amdb.get_user_by_nin("22222222222")
        assert res.user_id == self.user2.user_id, "gamma"

        assert self.amdb.get_user_by_nin("33333333333") is None, "delta"

        res = self.amdb.get_users_by_nin("33333333333", include_unconfirmed=True)
        assert [x.user_id for x in res] == [self.user3.user_id], "epsilon"

    def test_get_user_by_nin_unknown(self):
        """Test searching for unknown e-nin address"""
        assert self.amdb.get_user_by_nin("77777777777") is None

    def test_get_user_by_nin_multiple(self):
        # create another user with nin 33333333333, this one verified
        data4 = {
            "_id": bson.ObjectId(),
            "eduPersonPrincipalName": "nin-test4",
            "mail": "anka@example.com",
            "nins": [
                {"number": "33333333333", "primary": True, "verified": True},
            ],
            "passwords": [signup_password.to_dict()],
        }
        user4 = User.from_dict(data4)
        self.amdb.save(user4)

        res = self.amdb.get_users_by_nin("33333333333")
        ids = [x.user_id for x in res]
        assert ids == [user4.user_id]

        res = self.amdb.get_users_by_nin("33333333333", include_unconfirmed=True)
        assert [x.user_id for x in res] == [self.user3.user_id, user4.user_id]
