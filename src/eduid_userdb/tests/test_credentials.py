from unittest import TestCase

from bson.objectid import ObjectId
import eduid_userdb.exceptions
import eduid_userdb.element
from eduid_userdb.password import Password
from eduid_userdb.credentials import CredentialList

__author__ = 'lundberg'

#{'passwords': {
#    'id': password_id,
#    'salt': salt,
#    'source': 'signup',
#    'created_ts': datetime.datetime.utcnow(),
#}}

_one_dict = {
    'id': ObjectId('111111111111111111111111'),
    'salt': 'firstPasswordElement',
}
_two_dict = {
    'id': ObjectId('222222222222222222222222'),
    'salt': 'secondPasswordElement',
    'source': 'test'
}
_three_dict = {
    'id': ObjectId('333333333333333333333333'),
    'salt': 'thirdPasswordElement',
    'source': 'test'
}


class TestCredentialList(TestCase):

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
        match = self.two.find(ObjectId('222222222222222222222222'))
        self.assertIsInstance(match, Password)
        self.assertEqual(match.id, ObjectId('222222222222222222222222'))
        self.assertEqual(match.salt, 'secondPasswordElement')
        self.assertEqual(match.created_by, 'test')

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

