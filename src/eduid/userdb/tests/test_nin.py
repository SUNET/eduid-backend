import copy
import datetime
import unittest
from unittest import TestCase

import pytest
from pydantic import ValidationError

import eduid.userdb.exceptions
from eduid.userdb import PhoneNumber
from eduid.userdb.element import ElementKey
from eduid.userdb.nin import Nin, NinList

__author__ = 'ft'

_one_dict = {
    'number': '197801011234',
    'primary': True,
    'verified': True,
}

_two_dict = {
    'number': '197802022345',
    'primary': False,
    'verified': True,
}

_three_dict = {
    'number': '197803033456',
    'primary': False,
    'verified': False,
}


class TestNinList(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None  # Make pytest show full diffs
        self.empty = NinList()
        self.one = NinList.from_list_of_dicts([_one_dict])
        self.two = NinList.from_list_of_dicts([_one_dict, _two_dict])
        self.three = NinList.from_list_of_dicts([_one_dict, _two_dict, _three_dict])

    def test_init_bad_data(self):
        with pytest.raises(ValidationError):
            NinList(elements='bad input data')
        with pytest.raises(ValidationError):
            NinList(elements=['bad input data'])

    def test_to_list(self):
        self.assertEqual([], self.empty.to_list(), list)
        self.assertIsInstance(self.one.to_list(), list)

        self.assertEqual(1, len(self.one.to_list()))

    def test_to_list_of_dicts(self):
        self.assertEqual([], self.empty.to_list_of_dicts(), list)

    def test_find(self):
        match = self.one.find(ElementKey('197801011234'))
        self.assertIsInstance(match, Nin)
        self.assertEqual(match.number, '197801011234')
        self.assertEqual(match.is_verified, True)
        self.assertEqual(match.verified_ts, None)

    def test_add(self):
        second = self.two.find(ElementKey('197802022345'))
        self.one.add(second)

        expected = self.two.to_list_of_dicts()
        obtained = self.one.to_list_of_dicts()

        assert obtained == expected, 'List with removed NIN has unexpected data'

    def test_add_duplicate(self) -> None:
        assert isinstance(self.two, NinList)
        dup = self.two.find(self.two.primary.key)
        with pytest.raises(ValidationError) as exc_info:
            self.two.add(dup)

        assert exc_info.value.errors() == [
            {'loc': ('elements',), 'msg': 'Duplicate element key: \'197801011234\'', 'type': 'value_error'}
        ]

    def test_add_nin(self):
        third = self.three.find(ElementKey('197803033456'))
        this = NinList.from_list_of_dicts([_one_dict, _two_dict, third.to_dict()])

        expected = self.three.to_list_of_dicts()
        obtained = this.to_list_of_dicts()

        assert obtained == expected, 'List with added nin has unexpected data'

    def test_add_another_primary(self):
        new = eduid.userdb.nin.nin_from_dict({'number': '+46700000009', 'verified': True, 'primary': True})
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            self.one.add(new)

    def test_add_wrong_type(self):
        """ Test adding a phone number to the nin-list.
        Specifically phone, since pydantic can coerce it into a nin since they both have the 'number' field.
        """
        new = PhoneNumber(number='+4612345678')
        with pytest.raises(ValidationError) as exc_info:
            self.one.add(new)
        assert exc_info.value.errors() == [
            {
                'loc': ('elements',),
                'msg': "Value of type <class 'eduid.userdb.phone.PhoneNumber'> is not an "
                "<class 'eduid.userdb.nin.Nin'>",
                'type': 'type_error',
            }
        ]

    def test_remove(self):
        self.three.remove(ElementKey('197803033456'))
        now_two = self.three

        expected = self.two.to_list_of_dicts()
        obtained = now_two.to_list_of_dicts()

        assert obtained == expected, 'List with removed NIN has unexpected data'

    def test_remove_unknown(self):
        with self.assertRaises(eduid.userdb.exceptions.UserDBValueError):
            self.one.remove(ElementKey('+46709999999'))

    def test_remove_primary(self):
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            self.two.remove(self.two.primary.key)

    def test_remove_primary_single(self):
        self.one.remove(self.one.primary.key)
        now_empty = self.one
        self.assertEqual([], now_empty.to_list())

    def test_primary(self):
        match = self.one.primary
        self.assertEqual(match.number, '197801011234')

    def test_empty_primary(self):
        self.assertEqual(None, self.empty.primary)

    def test_set_primary_to_same(self):
        match = self.one.primary
        self.one.set_primary(match.key)

        match = self.two.primary
        self.two.set_primary(match.key)

    def test_set_unknown_as_primary(self):
        with self.assertRaises(eduid.userdb.exceptions.UserDBValueError):
            self.one.set_primary(ElementKey('+46709999999'))

    def test_set_unverified_as_primary(self):
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            self.three.set_primary(ElementKey('197803033456'))

    def test_change_primary(self):
        match = self.two.primary
        self.assertEqual(match.number, '197801011234')
        self.two.set_primary(ElementKey('197802022345'))
        updated = self.two.primary
        self.assertEqual(updated.number, '197802022345')

    def test_bad_input_two_primary(self):
        one = copy.deepcopy(_one_dict)
        two = copy.deepcopy(_two_dict)
        one['primary'] = True
        two['primary'] = True
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            NinList.from_list_of_dicts([one, two])

    def test_bad_input_unverified_primary(self):
        one = copy.deepcopy(_one_dict)
        one['verified'] = False
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            NinList.from_list_of_dicts([one])


class TestNin(TestCase):
    def setUp(self):
        self.empty = NinList()
        self.one = NinList.from_list_of_dicts([_one_dict])
        self.two = NinList.from_list_of_dicts([_one_dict, _two_dict])
        self.three = NinList.from_list_of_dicts([_one_dict, _two_dict, _three_dict])

    def test_key(self):
        """
        Test that the 'key' property (used by PrimaryElementList) works for the Nin.
        """
        address = self.two.primary
        self.assertEqual(address.key, address.number)

    def test_parse_cycle(self):
        """
        Tests that we output something we parsed back into the same thing we output.
        """
        for this in [self.one, self.two, self.three]:
            this_dict = this.to_list_of_dicts()
            self.assertEqual(NinList.from_list_of_dicts(this_dict).to_list_of_dicts(), this.to_list_of_dicts())

    def test_changing_is_verified_on_primary(self):
        this = self.one.primary
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            this.is_verified = False

    def test_changing_is_verified(self):
        this = self.three.find(ElementKey('197803033456'))
        this.is_verified = False  # was False already
        this.is_verified = True

    def test_verified_by(self):
        this = self.three.find(ElementKey('197803033456'))
        this.verified_by = 'unit test'
        self.assertEqual(this.verified_by, 'unit test')

    def test_modify_verified_by(self):
        this = self.three.find(ElementKey('197803033456'))
        this.verified_by = 'unit test'
        this.verified_by = 'test unit'
        self.assertEqual(this.verified_by, 'test unit')

    def test_modify_verified_ts(self):
        this = self.three.find(ElementKey('197803033456'))
        now = datetime.datetime.utcnow()
        this.verified_ts = now
        self.assertEqual(this.verified_ts, now)

    def test_created_by(self):
        this = self.three.find(ElementKey('197803033456'))
        this.created_by = 'unit test'
        self.assertEqual(this.created_by, 'unit test')

    def test_modify_created_by(self):
        this = self.three.find(ElementKey('197803033456'))
        this.created_by = 'unit test'

        assert this.created_by == 'unit test'

    def test_created_ts(self):
        this = self.three.find(ElementKey('197803033456'))
        self.assertIsInstance(this.created_ts, datetime.datetime)
