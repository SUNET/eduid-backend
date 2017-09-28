from unittest import TestCase

import copy
import datetime
from bson.objectid import ObjectId
import eduid_userdb.exceptions
import eduid_userdb.element
from eduid_userdb.password import Password
from eduid_userdb.credentials import CredentialList
from eduid_userdb.actions.chpass import ChpassUser, ChpassUserDB
from eduid_userdb.exceptions import UserMissingData, UserHasUnknownData

__author__ = 'lundberg'

#{'passwords': {
#    'id': password_id,
#    'salt': salt,
#    'source': 'signup',
#    'created_ts': datetime.datetime.utcnow(),
#}}

_one_dict = {
    'id': ObjectId('55002741d00690878ae9b600'),
    'salt': 'firstPasswordElement',
}
_two_dict = {
    'id': ObjectId('55002741d00690878ae9b601'),
    'salt': 'secondPasswordElement',
    'source': 'test'
}
_three_dict = {
    'id': ObjectId('55002741d00690878ae9b602'),
    'salt': 'thirdPasswordElement',
    'source': 'test'
}


class TestPasswordList(TestCase):

    def setUp(self):
        self.empty = CredentialList([])

        self.one = CredentialList([_one_dict])

        self.two = CredentialList([_one_dict, _two_dict])

        self.three = CredentialList([_one_dict, _two_dict, _three_dict])

    def test_to_list(self):
        self.assertEqual([], self.empty.to_list(), list)
        self.assertIsInstance(self.one.to_list(), list)

        self.assertEqual(1, len(self.one.to_list()))

    def test_to_list_of_dicts(self):
        self.assertEqual([], self.empty.to_list_of_dicts(), list)

        self.assertEqual([_one_dict], self.one.to_list_of_dicts(old_userdb_format=True))

    def test_find(self):
        match = self.two.find(ObjectId('55002741d00690878ae9b601'))
        self.assertIsInstance(match, Password)
        self.assertEqual(match.id, ObjectId('55002741d00690878ae9b601'))
        self.assertEqual(match.salt, 'secondPasswordElement')
        self.assertEqual(match.created_by, 'test')

    def test_add(self):
        second = self.two.find(ObjectId('55002741d00690878ae9b601'))
        self.one.add(second)
        self.assertEqual(self.one.to_list_of_dicts(), self.two.to_list_of_dicts())

    def test_add_duplicate(self):
        dup = self.two.find(ObjectId('55002741d00690878ae9b601'))
        with self.assertRaises(eduid_userdb.element.DuplicateElementViolation):
            self.two.add(dup)

    def test_add_password(self):
        third = self.three.find(ObjectId('55002741d00690878ae9b602'))
        this = CredentialList([_one_dict, _two_dict] + [third])
        self.assertEqual(this.to_list_of_dicts(), self.three.to_list_of_dicts())

    def test_remove(self):
        now_two = self.three.remove(ObjectId('55002741d00690878ae9b602'))
        self.assertEqual(self.two.to_list_of_dicts(), now_two.to_list_of_dicts())

    def test_remove_unknown(self):
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            self.one.remove(ObjectId('55002741d00690878ae9b603'))


class TestPassword(TestCase):

    def setUp(self):
        self.empty = CredentialList([])
        self.one = CredentialList([_one_dict])
        self.two = CredentialList([_one_dict, _two_dict])
        self.three = CredentialList([_one_dict, _two_dict, _three_dict])

    def test_key(self):
        """
        Test that the 'key' property (used by CredentialList) works for the Password.
        """
        password = self.one.find(ObjectId('55002741d00690878ae9b600'))
        self.assertEqual(password.key, password.id)

    def test_setting_invalid_password(self):
        this = self.one.find(ObjectId('55002741d00690878ae9b600'))
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.id = None

    def test_setting_invalid_salt(self):
        this = self.one.find(ObjectId('55002741d00690878ae9b600'))
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.salt = None

    def test_parse_cycle(self):
        """
        Tests that we output something we parsed back into the same thing we output.
        """
        for this in [self.one, self.two, self.three]:
            this_dict = this.to_list_of_dicts()
            self.assertEqual(CredentialList(this_dict).to_list_of_dicts(), this.to_list_of_dicts())

    def test_unknown_input_data(self):
        one = copy.deepcopy(_one_dict)
        one['foo'] = 'bar'
        with self.assertRaises(eduid_userdb.exceptions.UserHasUnknownData):
            Password(data=one)

    def test_unknown_input_data_allowed(self):
        one = copy.deepcopy(_one_dict)
        one['foo'] = 'bar'
        addr = Password(data=one, raise_on_unknown=False)
        out = addr.to_dict()
        self.assertIn('foo', out)
        self.assertEqual(out['foo'], one['foo'])

    def test_created_by(self):
        this = self.three.find(ObjectId('55002741d00690878ae9b600'))
        this.created_by = 'unit test'
        self.assertEqual(this.created_by, 'unit test')
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_by = False

    def test_modify_created_by(self):
        this = self.three.find(ObjectId('55002741d00690878ae9b600'))
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_by = 1
        this.created_by = 'unit test'
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_by = None
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_by = 'test unit'

    def test_created_ts(self):
        this = self.three.find(ObjectId('55002741d00690878ae9b600'))
        this.created_ts = True
        self.assertIsInstance(this.created_ts, datetime.datetime)
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_ts = False

    def test_modify_created_ts(self):
        this = self.three.find(ObjectId('55002741d00690878ae9b600'))
        this.created_ts = datetime.datetime.utcnow()
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_ts = None
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_ts = True


USERID = '123467890123456789014567'


class TestChpassUser(TestCase):

    def test_proper_user(self):
        one = copy.deepcopy(_one_dict)
        password = Password(data = one, raise_on_unknown = False)
        user = ChpassUser(userid=USERID, passwords=[password])
        self.assertEquals(user.passwords.to_list_of_dicts()[0]['salt'],
                'firstPasswordElement')

    def test_missing_userid(self):
        one = copy.deepcopy(_one_dict)
        password = Password(data = one, raise_on_unknown = False)
        with self.assertRaises(UserMissingData):
            user = ChpassUser(passwords=[password])

    def test_missing_tou(self):
        with self.assertRaises(UserMissingData):
            user = ChpassUser(userid=USERID)

    def test_unknown_data(self):
        one = copy.deepcopy(_one_dict)
        password = Password(data = one, raise_on_unknown = False)
        data = dict(_id=USERID, passwords=[password], foo='bar')
        with self.assertRaises(UserHasUnknownData):
            user = ChpassUser(data=data)

    def test_unknown_data_dont_raise(self):
        one = copy.deepcopy(_one_dict)
        password = Password(data = one, raise_on_unknown = False)
        data = dict(_id=USERID, passwords=[password], foo='bar')
        user = ChpassUser(data=data, raise_on_unknown=False)
        self.assertEquals(user.to_dict()['foo'], 'bar')
