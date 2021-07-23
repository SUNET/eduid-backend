import datetime
from unittest import TestCase

from bson.objectid import ObjectId

from eduid.userdb.credentials import CredentialList

__author__ = 'lundberg'


_one_dict = {
    'id': '55002741d00690878ae9b600',
    'salt': 'firstPasswordElement',
}
_two_dict = {'id': '55002741d00690878ae9b601', 'salt': 'secondPasswordElement', 'source': 'test'}
_three_dict = {'id': '55002741d00690878ae9b602', 'salt': 'thirdPasswordElement', 'source': 'test'}


class TestPassword(TestCase):
    def setUp(self):
        self.empty = CredentialList()
        self.one = CredentialList.from_list_of_dicts([_one_dict])
        self.two = CredentialList.from_list_of_dicts([_one_dict, _two_dict])
        self.three = CredentialList.from_list_of_dicts([_one_dict, _two_dict, _three_dict])

    def test_key(self):
        """
        Test that the 'key' property (used by CredentialList) works for the Password.
        """
        password = self.one.find(ObjectId('55002741d00690878ae9b600'))
        self.assertEqual(password.key, password.credential_id)

    def test_parse_cycle(self):
        """
        Tests that we output something we parsed back into the same thing we output.
        """
        for this in [self.one, self.two, self.three]:
            this_dict = this.to_list_of_dicts()
            self.assertEqual(CredentialList.from_list_of_dicts(this_dict).to_list_of_dicts(), this.to_list_of_dicts())

    def test_created_by(self):
        this = self.three.find(ObjectId('55002741d00690878ae9b600'))
        this.created_by = 'unit test'
        self.assertEqual(this.created_by, 'unit test')

    def test_created_ts(self):
        this = self.three.find(ObjectId('55002741d00690878ae9b600'))
        self.assertIsInstance(this.created_ts, datetime.datetime)
