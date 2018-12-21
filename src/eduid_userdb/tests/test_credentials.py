from unittest import TestCase

from hashlib import sha256
from bson.objectid import ObjectId

import eduid_userdb.exceptions
import eduid_userdb.element
from eduid_userdb.credentials import CredentialList, U2F, Password

__author__ = 'lundberg'

#{'passwords': {
#    'id': password_id,
#    'salt': salt,
#    'source': 'signup',
#    'created_ts': datetime.datetime.utcnow(),
#}}

_one_dict = {
    'credential_id': '111111111111111111111111',
    'salt': 'firstPasswordElement',
}
_two_dict = {
    'credential_id': '222222222222222222222222',
    'salt': 'secondPasswordElement',
    'source': 'test',
}
_three_dict = {
    'credential_id': '333333333333333333333333',
    'salt': 'thirdPasswordElement',
    'source': 'test',
}
_four_dict = {
    'version': 'U2F_V2',
    'app_id': 'unit test',
    'keyhandle': 'firstU2FElement',
    'public_key': 'foo',
}

def _keyid(key):
    return 'sha256:' + sha256(key['keyhandle'].encode('utf-8') +
                              key['public_key'].encode('utf-8')).hexdigest()


class TestCredentialList(TestCase):

    def setUp(self):
        self.empty = CredentialList([])
        self.one = CredentialList([_one_dict])
        self.two = CredentialList([_one_dict, _two_dict])
        self.three = CredentialList([_one_dict, _two_dict, _three_dict])
        self.four = CredentialList([_one_dict, _two_dict, _three_dict, _four_dict])

    def test_to_list(self):
        self.assertEqual([], self.empty.to_list(), list)
        self.assertIsInstance(self.one.to_list(), list)

        self.assertEqual(1, len(self.one.to_list()))
        self.assertEqual(4, len(self.four.to_list()))

    def test_to_list_of_dicts(self):
        self.assertEqual([], self.empty.to_list_of_dicts(), list)

        self.assertEqual([_one_dict], self.one.to_list_of_dicts(old_userdb_format=True))

    def test_find(self):
        match = self.two.find('222222222222222222222222')
        self.assertIsInstance(match, Password)
        self.assertEqual(match.credential_id, '222222222222222222222222')
        self.assertEqual(match.salt, 'secondPasswordElement')
        self.assertEqual(match.created_by, 'test')

    def test_find_with_objectid(self):
        """ Test that backwards compatibility in find() works """
        first = self.two.find('222222222222222222222222')
        second = self.two.find(ObjectId('222222222222222222222222'))
        self.assertEqual(first, second)

    def test_filter(self):
        match = self.four.filter(U2F)
        self.assertEqual(match.count, 1)
        token = match.to_list()[0]
        self.assertEqual(token.key, _keyid(_four_dict))
        self.assertEqual(token.public_key, 'foo')

    def test_add(self):
        second = self.two.find(ObjectId('222222222222222222222222'))
        self.one.add(second)
        self.assertEqual(self.one.to_list_of_dicts(), self.two.to_list_of_dicts())

    def test_add_duplicate(self):
        dup = self.two.find(ObjectId('222222222222222222222222'))
        with self.assertRaises(eduid_userdb.element.DuplicateElementViolation):
            self.two.add(dup)

    def test_add_password(self):
        third = self.three.find(ObjectId('333333333333333333333333'))
        this = CredentialList([_one_dict, _two_dict] + [third])
        self.assertEqual(this.to_list_of_dicts(), self.three.to_list_of_dicts())

    def test_remove(self):
        now_two = self.three.remove(ObjectId('333333333333333333333333'))
        self.assertEqual(self.two.to_list_of_dicts(), now_two.to_list_of_dicts())

    def test_remove_unknown(self):
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            self.one.remove(ObjectId('55002741d00690878ae9b603'))

