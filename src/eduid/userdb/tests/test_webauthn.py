import datetime
from hashlib import sha256
from unittest import TestCase

from eduid.userdb.credentials import CredentialList

__author__ = 'lundberg'

_one_dict = {
    'app_id': 'unit test',
    'keyhandle': 'firstWebauthnElement',
    'credential_data': 'bar',
    'attest_obj': 'foo',
}
_two_dict = {
    'app_id': 'unit test',
    'keyhandle': 'secondWebauthnElement',
    'credential_data': 'bar',
    'attest_obj': 'foo',
}
_three_dict = {
    'app_id': 'unit test',
    'keyhandle': 'thirdWebauthnElement',
    'credential_data': 'bar',
    'attest_obj': 'foo',
}


def _keyid(key):
    return 'sha256:' + sha256(key['keyhandle'].encode('utf-8') + key['credential_data'].encode('utf-8')).hexdigest()


class TestWebauthn(TestCase):
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
        self.assertEqual(
            this.key,
            _keyid(
                {
                    'keyhandle': this.keyhandle,
                    'attestation_object': this.attest_obj,
                    'credential_data': this.credential_data,
                }
            ),
        )

    def test_parse_cycle(self):
        """
        Tests that we output something we parsed back into the same thing we output.
        """
        for this in [self.one, self.two, self.three]:
            this_dict = this.to_list_of_dicts()
            self.assertEqual(CredentialList(this_dict).to_list_of_dicts(), this.to_list_of_dicts())

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
