from unittest import TestCase

import copy
import datetime
import eduid_userdb.exceptions
import eduid_userdb.element

from hashlib import sha256
from eduid_userdb.credentials import CredentialList, U2F

__author__ = 'lundberg'

#{'passwords': {
#    'id': password_id,
#    'salt': salt,
#    'source': 'signup',
#    'created_ts': datetime.datetime.utcnow(),
#}}

_one_dict = {
    'version': 'U2F_V2',
    'app_id': 'unit test',
    'keyhandle': 'firstU2FElement',
    'public_key': 'foo',
}
_two_dict = {
    'version': 'U2F_V2',
    'app_id': 'unit test',
    'keyhandle': 'secondU2FElement',
    'public_key': 'foo',
}
_three_dict = {
    'version': 'U2F_V2',
    'app_id': 'unit test',
    'keyhandle': 'thirdU2FElement',
    'public_key': 'foo',
}

def _keyid(kh):
    return 'sha256:' + sha256(kh.encode('utf-8')).hexdigest()


class TestU2F(TestCase):

    def setUp(self):
        self.empty = CredentialList([])
        self.one = CredentialList([_one_dict])
        self.two = CredentialList([_one_dict, _two_dict])
        self.three = CredentialList([_one_dict, _two_dict, _three_dict])

    def test_key(self):
        """
        Test that the 'key' property (used by CredentialList) works for the credential.
        """
        this = self.one.find(_keyid('firstU2FElement'))
        self.assertEqual(this.key, _keyid(this.keyhandle))

    def test_setting_invalid_keyhandle(self):
        this = self.one.find(_keyid('firstU2FElement'))
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.keyhandle = None

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
            U2F(data=one)

    def test_unknown_input_data_allowed(self):
        one = copy.deepcopy(_one_dict)
        one['foo'] = 'bar'
        addr = U2F(data=one, raise_on_unknown=False)
        out = addr.to_dict()
        self.assertIn('foo', out)
        self.assertEqual(out['foo'], one['foo'])

    def test_created_by(self):
        this = self.three.find(_keyid('thirdU2FElement'))
        this.created_by = 'unit test'
        self.assertEqual(this.created_by, 'unit test')
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_by = False

    def test_modify_created_by(self):
        this = self.three.find(_keyid('thirdU2FElement'))
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_by = 1
        this.created_by = 'unit test'
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_by = None
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_by = 'test unit'

    def test_created_ts(self):
        this = self.three.find(_keyid('thirdU2FElement'))
        this.created_ts = True
        self.assertIsInstance(this.created_ts, datetime.datetime)
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_ts = False

    def test_modify_created_ts(self):
        this = self.three.find(_keyid('thirdU2FElement'))
        this.created_ts = datetime.datetime.utcnow()
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_ts = None
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_ts = True

    def test_proofing_method(self):
        this = self.three.find(_keyid('thirdU2FElement'))
        this.proofing_method = 'TEST'
        self.assertEqual(this.proofing_method, 'TEST')
        this.proofing_method = 'TEST2'
        self.assertEqual(this.proofing_method, 'TEST2')
        this.proofing_method = None
        self.assertEqual(this.proofing_method, None)
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.proofing_method = False


    def test_proofing_version(self):
        this = self.three.find(_keyid('thirdU2FElement'))
        this.proofing_version = 'TEST'
        self.assertEqual(this.proofing_version, 'TEST')
        this.proofing_version = 'TEST2'
        self.assertEqual(this.proofing_version, 'TEST2')
        this.proofing_version = None
        self.assertEqual(this.proofing_version, None)
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.proofing_version = False
