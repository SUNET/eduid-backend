import copy
import datetime
from unittest import TestCase

import bson

import eduid_userdb.element
import eduid_userdb.exceptions
from eduid_userdb.credentials import Password
from eduid_userdb.mail import MailAddress, MailAddressList

__author__ = 'ft'

_one_dict = {
    'email': 'ft@one.example.org',
    'primary': True,
    'verified': True,
}

_two_dict = {
    'email': 'ft@two.example.org',
    'primary': False,
    'verified': True,
}

_three_dict = {
    'email': 'ft@three.example.org',
    'primary': False,
    'verified': False,
}


class TestMailAddressList(TestCase):
    def setUp(self):
        self.empty = MailAddressList([])
        self.one = MailAddressList([_one_dict])
        self.two = MailAddressList([_one_dict, _two_dict])
        self.three = MailAddressList([_one_dict, _two_dict, _three_dict])

    def test_init_bad_data(self):
        with self.assertRaises(eduid_userdb.element.UserDBValueError):
            MailAddressList('bad input data')

    def test_to_list(self):
        self.assertEqual([], self.empty.to_list(), list)
        self.assertIsInstance(self.one.to_list(), list)

        self.assertEqual(1, len(self.one.to_list()))

    def test_to_list_of_dicts(self):
        self.assertEqual([], self.empty.to_list_of_dicts(), list)

        self.assertEqual([_one_dict], self.one.to_list_of_dicts())

    def test_find(self):
        match = self.one.find('ft@one.example.org')
        self.assertIsInstance(match, MailAddress)
        self.assertEqual(match.email, 'ft@one.example.org')
        self.assertEqual(match.is_verified, True)
        self.assertEqual(match.verified_ts, None)

    def test_add(self):
        second = self.two.find('ft@two.example.org')
        self.one.add(second)
        self.assertEqual(self.one.to_list_of_dicts(), self.two.to_list_of_dicts())

    def test_add_duplicate(self):
        dup = self.two.find(self.two.primary.email)
        with self.assertRaises(eduid_userdb.element.DuplicateElementViolation):
            self.two.add(dup)

    def test_add_mailaddress(self):
        third = self.three.find('ft@three.example.org')
        this = MailAddressList([_one_dict, _two_dict, third])
        self.assertEqual(this.to_list_of_dicts(), self.three.to_list_of_dicts())

    def test_add_another_primary(self):
        new = eduid_userdb.mail.address_from_dict(
            {'email': 'ft@primary.example.org', 'verified': True, 'primary': True,}
        )
        with self.assertRaises(eduid_userdb.element.PrimaryElementViolation):
            self.one.add(new)

    def test_add_wrong_type(self):
        pwdict = {
            'id': bson.ObjectId(),
            'salt': 'foo',
        }
        new = Password.from_dict(pwdict)
        with self.assertRaises(eduid_userdb.element.UserDBValueError):
            self.one.add(new)

    def test_remove(self):
        now_two = self.three.remove('ft@three.example.org')
        self.assertEqual(self.two.to_list_of_dicts(), now_two.to_list_of_dicts())

    def test_remove_unknown(self):
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            self.one.remove('foo@no-such-address.example.org')

    def test_remove_primary(self):
        with self.assertRaises(eduid_userdb.element.PrimaryElementViolation):
            self.two.remove(self.two.primary.email)

    def test_remove_primary_single(self):
        now_empty = self.one.remove(self.one.primary.email)
        self.assertEqual([], now_empty.to_list())

    def test_primary(self):
        match = self.one.primary
        self.assertEqual(match.email, 'ft@one.example.org')

    def test_empty_primary(self):
        self.assertEqual(None, self.empty.primary)

    def test_set_primary_to_same(self):
        match = self.one.primary
        self.one.primary = match.email

        match = self.two.primary
        self.two.primary = match.email

    def test_set_unknown_as_primary(self):
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            self.one.primary = 'foo@no-such-address.example.org'

    def test_set_unverified_as_primary(self):
        with self.assertRaises(eduid_userdb.element.PrimaryElementViolation):
            self.three.primary = 'ft@three.example.org'

    def test_change_primary(self):
        match = self.two.primary
        self.assertEqual(match.email, 'ft@one.example.org')
        self.two.primary = 'ft@two.example.org'
        updated = self.two.primary
        self.assertEqual(updated.email, 'ft@two.example.org')

    def test_bad_input_two_primary(self):
        one = copy.deepcopy(_one_dict)
        two = copy.deepcopy(_two_dict)
        one['primary'] = True
        two['primary'] = True
        with self.assertRaises(eduid_userdb.element.PrimaryElementViolation):
            MailAddressList([one, two])

    def test_bad_input_unverified_primary(self):
        one = copy.deepcopy(_one_dict)
        one['verified'] = False
        with self.assertRaises(eduid_userdb.element.PrimaryElementViolation):
            MailAddressList([one])


class TestMailAddress(TestCase):
    def setUp(self):
        self.empty = MailAddressList([])
        self.one = MailAddressList([_one_dict])
        self.two = MailAddressList([_one_dict, _two_dict])
        self.three = MailAddressList([_one_dict, _two_dict, _three_dict])

    def test_key(self):
        """
        Test that the 'key' property (used by PrimaryElementList) works for the MailAddress.
        """
        address = self.two.primary
        self.assertEqual(address.key, address.email)

    def test_parse_cycle(self):
        """
        Tests that we output something we parsed back into the same thing we output.
        """
        for this in [self.one, self.two, self.three]:
            this_dict = this.to_list_of_dicts()
            self.assertEqual(MailAddressList(this_dict).to_list_of_dicts(), this.to_list_of_dicts())

    def test_unknown_input_data(self):
        one = copy.deepcopy(_one_dict)
        one['foo'] = 'bar'
        with self.assertRaises(eduid_userdb.exceptions.UserHasUnknownData):
            MailAddress.from_dict(one)

    def test_unknown_input_data_allowed(self):
        one = copy.deepcopy(_one_dict)
        one['foo'] = 'bar'
        addr = MailAddress.from_dict(data=one, raise_on_unknown=False)
        out = addr.to_dict()
        self.assertIn('foo', out)
        self.assertEqual(out['foo'], one['foo'])

    def test_changing_is_verified_on_primary(self):
        this = self.one.primary
        with self.assertRaises(eduid_userdb.element.PrimaryElementViolation):
            this.is_verified = False

    def test_changing_is_verified(self):
        this = self.three.find('ft@three.example.org')
        this.is_verified = False  # was False already
        this.is_verified = True

    def test_verified_by(self):
        this = self.three.find('ft@three.example.org')
        this.verified_by = 'unit test'
        self.assertEqual(this.verified_by, 'unit test')

    def test_modify_verified_by(self):
        this = self.three.find('ft@three.example.org')
        this.verified_by = 'unit test'
        this.verified_by = None
        self.assertEqual(this.verified_by, 'unit test')
        this.verified_by = 'test unit'
        self.assertEqual(this.verified_by, 'test unit')

    def test_verified_ts(self):
        this = self.three.find('ft@three.example.org')
        this.verified_ts = True
        self.assertIsInstance(this.verified_ts, datetime.datetime)

    def test_modify_verified_ts(self):
        this = self.three.find('ft@three.example.org')
        now = datetime.datetime.utcnow()
        this.verified_ts = now
        this.verified_ts = True
        self.assertGreater(this.verified_ts, now)
        this.verified_ts = now
        self.assertEqual(this.verified_ts, now)

    def test_created_by(self):
        this = self.three.find('ft@three.example.org')
        this.created_by = 'unit test'
        self.assertEqual(this.created_by, 'unit test')

    def test_created_ts(self):
        this = self.three.find('ft@three.example.org')
        this.created_ts = True
        self.assertIsInstance(this.created_ts, datetime.datetime)
