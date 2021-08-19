import copy
import datetime
import unittest
from typing import List
from unittest import TestCase

import pytest
from pydantic import BaseModel, Extra, ValidationError, validator

import eduid.userdb.element
import eduid.userdb.exceptions
from eduid.userdb import PhoneNumber
from eduid.userdb.element import Element
from eduid.userdb.mail import MailAddress, MailAddressList

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


class TestMailAddressList(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.empty = MailAddressList()
        self.one = MailAddressList.from_list_of_dicts([_one_dict])
        self.two = MailAddressList.from_list_of_dicts([_one_dict, _two_dict])
        self.three = MailAddressList.from_list_of_dicts([_one_dict, _two_dict, _three_dict])

    def test_init_bad_data(self):
        with pytest.raises(ValidationError):
            MailAddressList(elements='bad input data')
        with pytest.raises(ValidationError):
            MailAddressList(elements=['bad input data'])

    def test_to_list(self):
        self.assertEqual([], self.empty.to_list(), list)
        self.assertIsInstance(self.one.to_list(), list)

        self.assertEqual(1, len(self.one.to_list()))

    def test_empty_to_list_of_dicts(self):
        self.assertEqual([], self.empty.to_list_of_dicts(), list)

    def test_find(self):
        match = self.one.find('ft@one.example.org')
        self.assertIsInstance(match, MailAddress)
        self.assertEqual(match.email, 'ft@one.example.org')
        self.assertEqual(match.is_verified, True)
        self.assertEqual(match.verified_ts, None)

    def test_add(self):
        second = self.two.find('ft@two.example.org')
        self.one.add(second)

        expected = self.two.to_list_of_dicts()
        obtained = self.one.to_list_of_dicts()

        assert obtained == expected, 'Wrong data after adding mail address to list'

    def test_add_duplicate(self):
        dup = self.two.find(self.two.primary.email)
        with pytest.raises(ValidationError) as exc_info:
            self.two.add(dup)

        assert exc_info.value.errors() == [
            {'loc': ('elements',), 'msg': 'Duplicate element key: \'ft@one.example.org\'', 'type': 'value_error'}
        ]

    def test_add_mailaddress(self):
        third = self.three.find('ft@three.example.org')
        this = MailAddressList.from_list_of_dicts([_one_dict, _two_dict, third.to_dict()])

        expected = self.three.to_list_of_dicts()
        obtained = this.to_list_of_dicts()

        assert obtained == expected, 'Wrong data in mail address list'

    def test_add_another_primary(self):
        new = eduid.userdb.mail.address_from_dict(
            {'email': 'ft@primary.example.org', 'verified': True, 'primary': True}
        )
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            self.one.add(new)

    def test_add_wrong_type(self):
        new = PhoneNumber(number='+4612345678')
        with pytest.raises(ValidationError):
            self.one.add(new)

    def test_remove(self):
        self.three.remove('ft@three.example.org')
        now_two = self.three

        expected = self.two.to_list_of_dicts()
        obtained = now_two.to_list_of_dicts()

        assert obtained == expected, 'Wrong data after removing email from list'

    def test_remove_unknown(self):
        with self.assertRaises(eduid.userdb.exceptions.UserDBValueError):
            self.one.remove('foo@no-such-address.example.org')

    def test_remove_primary(self):
        with pytest.raises(
            eduid.userdb.element.PrimaryElementViolation, match='Removing the primary element is not allowed'
        ):
            self.two.remove(self.two.primary.key)

    def test_remove_primary_single(self):
        self.one.remove(self.one.primary.email)
        now_empty = self.one
        self.assertEqual([], now_empty.to_list())

    def test_primary(self):
        match = self.one.primary
        self.assertEqual(match.email, 'ft@one.example.org')

    def test_empty_primary(self):
        self.assertEqual(None, self.empty.primary)

    def test_set_primary_to_same(self):
        match = self.one.primary
        self.one.set_primary(match.email)

        match = self.two.primary
        self.two.set_primary(match.email)

    def test_set_unknown_as_primary(self):
        with self.assertRaises(eduid.userdb.exceptions.UserDBValueError):
            self.one.set_primary('foo@no-such-address.example.org')

    def test_set_unverified_as_primary(self):
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            self.three.set_primary('ft@three.example.org')

    def test_change_primary(self):
        match = self.two.primary
        self.assertEqual(match.email, 'ft@one.example.org')
        self.two.set_primary('ft@two.example.org')
        updated = self.two.primary
        self.assertEqual(updated.email, 'ft@two.example.org')

    def test_bad_input_two_primary(self):
        one = copy.deepcopy(_one_dict)
        two = copy.deepcopy(_two_dict)
        one['primary'] = True
        two['primary'] = True
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            MailAddressList.from_list_of_dicts([one, two])

    def test_bad_input_unverified_primary(self):
        one = copy.deepcopy(_one_dict)
        one['verified'] = False
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            MailAddressList.from_list_of_dicts([one])


class TestMailAddress(TestCase):
    def setUp(self):
        self.empty = MailAddressList()
        self.one = MailAddressList.from_list_of_dicts([_one_dict])
        self.two = MailAddressList.from_list_of_dicts([_one_dict, _two_dict])
        self.three = MailAddressList.from_list_of_dicts([_one_dict, _two_dict, _three_dict])

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
            this_list = this.to_list_of_dicts()

            expected = this.to_list_of_dicts()
            cycled = MailAddressList.from_list_of_dicts(this_list).to_list_of_dicts()

            assert cycled == expected

    def test_unknown_input_data(self):
        one = copy.deepcopy(_one_dict)
        one['foo'] = 'bar'
        with pytest.raises(ValidationError) as exc_info:
            MailAddress.from_dict(one)

        assert exc_info.value.errors() == [
            {'loc': ('foo',), 'msg': 'extra fields not permitted', 'type': 'value_error.extra'}
        ]

    def test_bad_input_type(self):
        one = copy.deepcopy(_one_dict)
        one['email'] = False
        with pytest.raises(ValidationError) as exc_info:
            MailAddress.from_dict(one)

        assert exc_info.value.errors() == [{'loc': ('email',), 'msg': 'must be a string', 'type': 'value_error'}]

    def test_changing_is_verified_on_primary(self):
        this = self.one.primary
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
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
        this.verified_by = 'test unit'
        self.assertEqual(this.verified_by, 'test unit')

    def test_verified_ts(self):
        this = self.three.find('ft@three.example.org')
        this.verified_ts = datetime.datetime.utcnow()
        self.assertIsInstance(this.verified_ts, datetime.datetime)

    def test_modify_verified_ts(self):
        this = self.three.find('ft@three.example.org')
        now = datetime.datetime.utcnow()
        this.verified_ts = now

    def test_created_by(self):
        this = self.three.find('ft@three.example.org')
        this.created_by = 'unit test'
        self.assertEqual(this.created_by, 'unit test')

    def test_created_ts(self):
        this = self.three.find('ft@three.example.org')
        self.assertIsInstance(this.created_ts, datetime.datetime)

    def test_uppercase_email_address(self):
        address = 'UPPERCASE@example.com'
        mail_address = MailAddress(email=address)
        self.assertEqual(address.lower(), mail_address.email)
