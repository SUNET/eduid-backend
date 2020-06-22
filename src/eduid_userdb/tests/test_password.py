import copy
import datetime
from unittest import TestCase

from bson.objectid import ObjectId

import eduid_userdb.element
import eduid_userdb.exceptions
from eduid_userdb.credentials import CredentialList, Password

__author__ = 'lundberg'


_one_dict = {
    'id': ObjectId('55002741d00690878ae9b600'),
    'salt': 'firstPasswordElement',
}
_two_dict = {'id': ObjectId('55002741d00690878ae9b601'), 'salt': 'secondPasswordElement', 'source': 'test'}
_three_dict = {'id': ObjectId('55002741d00690878ae9b602'), 'salt': 'thirdPasswordElement', 'source': 'test'}


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
        self.assertEqual(password.key, password.credential_id)

    def test_setting_invalid_password(self):
        this = self.one.find(ObjectId('55002741d00690878ae9b600'))
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.credential_id = None

    def test_setting_invalid_salt(self):
        this = self.one.find(ObjectId('55002741d00690878ae9b600'))
        self.assertNotEqual(this, False)
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
            Password.from_dict(one)

    def test_unknown_input_data_allowed(self):
        one = copy.deepcopy(_one_dict)
        one['foo'] = 'bar'
        addr = Password.from_dict(one, raise_on_unknown=False)
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
