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

from datetime import datetime

import bson

import eduid_userdb
from eduid_userdb import User
from eduid_userdb.testing import MongoTestCase


class TestUserDB(MongoTestCase):
    def setUp(self):
        super(TestUserDB, self).setUp(None, None)

    def test_get_user_by_id(self):
        """ Test get_user_by_id """
        res = self.amdb.get_user_by_id(self.user.user_id)
        self.assertEqual(self.user.user_id, res.user_id)

        res = self.amdb.get_user_by_id(str(self.user.user_id))
        self.assertEqual(self.user.user_id, res.user_id)

        res = self.amdb.get_user_by_id(str(bson.ObjectId()), raise_on_missing=False)
        self.assertEqual(None, res)

        res = self.amdb.get_user_by_id('not-a-valid-object-id')
        self.assertEqual(None, res)

    def test_get_user_by_nin(self):
        """ Test get_user_by_nin """
        test_user = self.amdb.get_user_by_id(self.user.user_id)
        test_user.given_name = 'Kalle Anka'
        self.amdb.save(test_user)
        res = self.amdb.get_user_by_nin(test_user.nins.primary.number)
        self.assertEqual(test_user.given_name, res.given_name)

    def test_remove_user_by_id(self):
        """ Test removing a user from the database

            NOTE: remove_user_by_id() should be moved to SignupUserDb
        """
        test_user = self.amdb.get_user_by_id(self.user.user_id)
        res = self.amdb.get_user_by_nin(test_user.nins.primary.number, return_list=True)
        self.assertEqual(res, [test_user])
        self.amdb.remove_user_by_id(test_user.user_id)
        res = self.amdb.get_user_by_nin(test_user.nins.primary.number, return_list=True, raise_on_missing=False)
        self.assertEqual(res, [])

    def test_get_user_by_eppn(self):
        """ Test user lookup using eppn """
        test_user = self.amdb.get_user_by_id(self.user.user_id)
        res = self.amdb.get_user_by_eppn(test_user.eppn)
        self.assertEqual(test_user.user_id, res.user_id)

    def test_get_user_by_eppn_not_found(self):
        """ Test user lookup using unknown """
        with self.assertRaises(eduid_userdb.exceptions.UserDoesNotExist):
            self.amdb.get_user_by_eppn('abc123')


class TestUserDB_mail(MongoTestCase):
    def setUp(self):
        super(TestUserDB_mail, self).setUp(None, None)
        data1 = {
            u'_id': bson.ObjectId(),
            u'eduPersonPrincipalName': u'mail-test1',
            u'mail': u'test@gmail.com',
            u'mailAliases': [{u'email': u'test@gmail.com', u'verified': True}],
            u'passwords': [],
        }

        data2 = {
            u'_id': bson.ObjectId(),
            u'eduPersonPrincipalName': u'mail-test2',
            u'mailAliases': [
                {u'email': u'test2@gmail.com', u'primary': True, u'verified': True},
                {u'email': u'test@gmail.com', u'verified': False},
            ],
            u'passwords': [],
        }

        self.user1 = User.from_dict(data1)
        self.user2 = User.from_dict(data2)

        self.amdb.save(self.user1, check_sync=False, old_format=False)
        self.amdb.save(self.user2, check_sync=False, old_format=False)

    def test_get_user_by_mail(self):
        test_user = self.amdb.get_user_by_id(self.user1.user_id)
        res = self.amdb.get_user_by_mail(test_user.mail_addresses.primary.email)
        self.assertEqual(test_user.user_id, res.user_id)

    def test_get_user_by_mail_unknown(self):
        """ Test searching for unknown e-mail address """
        with self.assertRaises(eduid_userdb.exceptions.UserDoesNotExist):
            self.amdb.get_user_by_mail('abc123@example.edu')

        res = self.amdb.get_user_by_mail('abc123@example.edu', raise_on_missing=False)
        self.assertEqual(res, None)

    def test_get_user_by_mail_multiple(self):
        res = self.amdb.get_user_by_mail('test@gmail.com', return_list=True)
        ids = [x.user_id for x in res]
        self.assertEqual(ids, [self.user1.user_id])

        res = self.amdb.get_user_by_mail('test@gmail.com', return_list=True, include_unconfirmed=True)
        ids = [x.user_id for x in res]
        self.assertEqual(ids, [self.user1.user_id, self.user2.user_id])

        with self.assertRaises(eduid_userdb.exceptions.MultipleUsersReturned):
            self.amdb.get_user_by_mail('test@gmail.com', include_unconfirmed=True)


class TestUserDB_phone(MongoTestCase):
    def setUp(self):
        super(TestUserDB_phone, self).setUp(None, None)
        data1 = {
            u'_id': bson.ObjectId(),
            u'eduPersonPrincipalName': u'phone-test1',
            u'mail': u'kalle@example.com',
            u'phone': [
                {u'number': u'+11111111111', u'primary': True, u'verified': True},
                {u'number': u'+22222222222', u'primary': False, u'verified': True},
            ],
            u'passwords': [],
        }
        data2 = {
            u'_id': bson.ObjectId(),
            u'eduPersonPrincipalName': u'phone-test2',
            u'mail': u'anka@example.com',
            u'phone': [
                {u'number': u'+11111111111', u'primary': True, u'verified': False},
                {u'number': u'+22222222222', u'primary': False, u'verified': False},
                {u'number': u'+33333333333', u'primary': False, u'verified': False},
            ],
            u'passwords': [],
        }

        self.user1 = User.from_dict(data1)
        self.user2 = User.from_dict(data2)
        self.amdb.save(self.user1, old_format=False)
        self.amdb.save(self.user2, old_format=False)

    def test_get_user_by_phone(self):
        test_user = self.amdb.get_user_by_id(self.user1.user_id)
        res = self.amdb.get_user_by_phone(test_user.phone_numbers.primary.number)
        self.assertEqual(test_user.user_id, res.user_id)

        res = self.amdb.get_user_by_phone('+22222222222')
        self.assertEqual(test_user.user_id, res.user_id)

        self.assertIsNone(self.amdb.get_user_by_phone(u'+33333333333', raise_on_missing=False))

        res = self.amdb.get_user_by_phone(u'+33333333333', include_unconfirmed=True)
        self.assertEqual(self.user2.user_id, res.user_id)

    def test_get_user_by_phone_old_format(self):
        """ Test compatibility code locating old style users """
        # Re-save the test users in old userdb format
        user1 = self.amdb.get_user_by_id(self.user1.user_id)
        user2 = self.amdb.get_user_by_id(self.user2.user_id)
        self.amdb.save(user1, old_format=True)
        self.amdb.save(user2, old_format=True)

        test_user = self.amdb.get_user_by_id(self.user1.user_id)
        res = self.amdb.get_user_by_phone(test_user.phone_numbers.primary.number)
        self.assertEqual(test_user.user_id, res.user_id)

        res = self.amdb.get_user_by_phone('+22222222222')
        self.assertEqual(test_user.user_id, res.user_id)

        self.assertIsNone(self.amdb.get_user_by_phone(u'+33333333333', raise_on_missing=False))

        res = self.amdb.get_user_by_phone(u'+33333333333', include_unconfirmed=True)
        self.assertEqual(self.user2.user_id, res.user_id)

    def test_get_user_by_phone_unknown(self):
        """ Test searching for unknown e-phone address """
        with self.assertRaises(eduid_userdb.exceptions.UserDoesNotExist):
            self.amdb.get_user_by_phone('abc123@example.edu')

        res = self.amdb.get_user_by_phone('abc123@example.edu', raise_on_missing=False)
        self.assertEqual(res, None)

    def test_get_user_by_phone_multiple(self):
        res = self.amdb.get_user_by_phone('+11111111111', return_list=True)
        ids = [x.user_id for x in res]
        self.assertEqual(ids, [self.user1.user_id])

        res = self.amdb.get_user_by_phone('+11111111111', return_list=True, include_unconfirmed=True)
        ids = [x.user_id for x in res]
        self.assertEqual(ids, [self.user1.user_id, self.user2.user_id])

        with self.assertRaises(eduid_userdb.exceptions.MultipleUsersReturned):
            self.amdb.get_user_by_phone('+11111111111', include_unconfirmed=True)


class TestUserDB_nin(MongoTestCase):
    def setUp(self):
        super(TestUserDB_nin, self).setUp(None, None)
        data1 = {
            u'_id': bson.ObjectId(),
            u'eduPersonPrincipalName': u'nin-test1',
            u'mail': u'kalle@example.com',
            u'nins': [
                {u'number': u'11111111111', u'primary': True, u'verified': True},
                {u'number': u'22222222222', u'primary': False, u'verified': False},
            ],
            u'passwords': [],
        }
        data2 = {
            u'_id': bson.ObjectId(),
            u'eduPersonPrincipalName': u'nin-test2',
            u'mail': u'anka@example.com',
            u'nins': [
                {u'number': u'11111111111', u'primary': False, u'verified': False},
                {u'number': u'22222222222', u'primary': True, u'verified': True},
                {u'number': u'33333333333', u'primary': False, u'verified': False},
            ],
            u'passwords': [],
        }

        self.user1 = User.from_dict(data1)
        self.user2 = User.from_dict(data2)
        self.amdb.save(self.user1, old_format=False)
        self.amdb.save(self.user2, old_format=False)

    def test_get_user_by_nin(self):
        test_user = self.amdb.get_user_by_id(self.user1.user_id)
        res = self.amdb.get_user_by_nin(test_user.nins.primary.number)
        self.assertEqual(test_user.user_id, res.user_id)

        res = self.amdb.get_user_by_nin('11111111111')
        self.assertEqual(test_user.user_id, res.user_id)

        res = self.amdb.get_user_by_nin('22222222222')
        self.assertEqual(self.user2.user_id, res.user_id)

        self.assertIsNone(self.amdb.get_user_by_nin(u'33333333333', raise_on_missing=False))

        res = self.amdb.get_user_by_nin(u'33333333333', include_unconfirmed=True)
        self.assertEqual(self.user2.user_id, res.user_id)

    def test_get_user_by_nin_unknown(self):
        """ Test searching for unknown e-nin address """
        with self.assertRaises(eduid_userdb.exceptions.UserDoesNotExist):
            self.amdb.get_user_by_nin('77777777777')

        res = self.amdb.get_user_by_nin('77777777777', raise_on_missing=False)
        self.assertEqual(res, None)

    def test_get_user_by_nin_multiple(self):
        res = self.amdb.get_user_by_nin('11111111111', return_list=True)
        ids = [x.user_id for x in res]
        self.assertEqual(ids, [self.user1.user_id])

        res = self.amdb.get_user_by_nin('11111111111', return_list=True, include_unconfirmed=True)
        ids = [x.user_id for x in res]
        self.assertEqual(ids, [self.user1.user_id, self.user2.user_id])

        with self.assertRaises(eduid_userdb.exceptions.MultipleUsersReturned):
            self.amdb.get_user_by_nin('11111111111', include_unconfirmed=True)
