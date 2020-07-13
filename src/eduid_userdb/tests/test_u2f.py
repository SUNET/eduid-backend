import copy
import datetime
from hashlib import sha256
from unittest import TestCase

import eduid_userdb.element
import eduid_userdb.exceptions
from eduid_userdb.credentials import U2F, CredentialList

__author__ = 'lundberg'

# {'passwords': {
#    'id': password_id,
#    'salt': salt,
#    'source': 'signup',
#    'created_ts': datetime.datetime.utcnow(),
# }}

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


def _keyid(key):
    return 'sha256:' + sha256(key['keyhandle'].encode('utf-8') + key['public_key'].encode('utf-8')).hexdigest()


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
        this = self.one.find(_keyid(_one_dict))
        self.assertEqual(this.key, _keyid({'keyhandle': this.keyhandle, 'public_key': this.public_key,}))

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
        with self.assertRaises(TypeError):
            U2F.from_dict(one)

    def test_created_by(self):
        this = self.three.find(_keyid(_three_dict))
        this.created_by = 'unit test'
        self.assertEqual(this.created_by, 'unit test')

    def test_created_ts(self):
        this = self.three.find(_keyid(_three_dict))
        self.assertIsInstance(this.created_ts, datetime.datetime)

    def test_proofing_method(self):
        this = self.three.find(_keyid(_three_dict))
        this.proofing_method = 'TEST'
        self.assertEqual(this.proofing_method, 'TEST')
        this.proofing_method = 'TEST2'
        self.assertEqual(this.proofing_method, 'TEST2')
        this.proofing_method = None
        self.assertEqual(this.proofing_method, None)

    def test_proofing_version(self):
        this = self.three.find(_keyid(_three_dict))
        this.proofing_version = 'TEST'
        self.assertEqual(this.proofing_version, 'TEST')
        this.proofing_version = 'TEST2'
        self.assertEqual(this.proofing_version, 'TEST2')
        this.proofing_version = None
        self.assertEqual(this.proofing_version, None)
