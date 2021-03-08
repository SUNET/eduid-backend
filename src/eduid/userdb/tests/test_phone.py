import copy
import datetime
import unittest

import eduid_userdb.element
import eduid_userdb.exceptions
from eduid_userdb.element import Element
from eduid_userdb.phone import PhoneNumber, PhoneNumberList

__author__ = 'ft'

_one_dict = {
    'number': '+46700000001',
    'primary': True,
    'verified': True,
}

_two_dict = {
    'number': '+46700000002',
    'primary': False,
    'verified': True,
}

_three_dict = {
    'number': '+46700000003',
    'primary': False,
    'verified': False,
}

_four_dict = {
    'number': '+46700000004',
    'primary': False,
    'verified': False,
}


class TestPhoneNumberList(unittest.TestCase):
    def setUp(self):
        self.empty = PhoneNumberList([])
        self.one = PhoneNumberList([_one_dict])
        self.two = PhoneNumberList([_one_dict, _two_dict])
        self.three = PhoneNumberList([_one_dict, _two_dict, _three_dict])
        self.four = PhoneNumberList([_three_dict, _four_dict])

    def test_init_bad_data(self):
        with self.assertRaises(eduid_userdb.element.UserDBValueError):
            PhoneNumberList('bad input data')

    def test_to_list(self):
        assert self.empty.to_list_of_dicts() == []
        assert isinstance(self.one.to_list(), list)

        assert len(self.one.to_list()) == 1

    def test_to_list_of_dicts(self):
        assert self.empty.to_list_of_dicts() == []

        one_dict_list = self.one.to_list_of_dicts()
        expected = [_one_dict]

        assert one_dict_list == expected

    def test_find(self):
        match = self.one.find('+46700000001')
        self.assertIsInstance(match, PhoneNumber)
        self.assertEqual(match.number, '+46700000001')
        self.assertEqual(match.is_verified, True)
        self.assertEqual(match.verified_ts, None)

    def test_add(self):
        second = self.two.find('+46700000002')
        self.one.add(second)
        expected = self.two.to_list_of_dicts()
        got = self.one.to_list_of_dicts()

        assert got == expected, 'Adding a phone number to a list results in wrong data'

    def test_add_duplicate(self):
        dup = self.two.find(self.two.primary.number)
        with self.assertRaises(eduid_userdb.element.DuplicateElementViolation):
            self.two.add(dup)

    def test_add_phonenumber(self):
        third = self.three.find('+46700000003')
        this = PhoneNumberList([_one_dict, _two_dict, third])

        expected = self.three.to_list_of_dicts()
        got = this.to_list_of_dicts()

        assert got == expected, 'Phone number list contains wrong data'

    def test_add_another_primary(self):
        new = eduid_userdb.phone.phone_from_dict({'number': '+46700000009', 'verified': True, 'primary': True,})
        with self.assertRaises(eduid_userdb.element.PrimaryElementViolation):
            self.one.add(new)

    def test_add_wrong_type(self):
        elemdict = {
            'created_by': 'foo',
        }
        new = Element.from_dict(elemdict)
        with self.assertRaises(eduid_userdb.element.UserDBValueError):
            self.one.add(new)

    def test_remove(self):
        now_two = self.three.remove('+46700000003')
        expected = self.two.to_list_of_dicts()
        got = now_two.to_list_of_dicts()

        assert got == expected, 'Phone list has wrong data after removing phone'

    def test_remove_unknown(self):
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            self.one.remove('+46709999999')

    def test_remove_primary(self):
        with self.assertRaises(eduid_userdb.element.PrimaryElementViolation):
            self.two.remove(self.two.primary.number)

    def test_remove_primary_single(self):
        now_empty = self.one.remove(self.one.primary.number)
        self.assertEqual([], now_empty.to_list())

    def test_remove_all_mix(self):
        verified = self.three.verified.to_list()
        if verified:
            for mobile in verified:
                if not mobile.is_primary:
                    self.three.remove(mobile.number)
            self.three.remove(self.three.primary.number)
        for mobile in self.three.to_list():
            self.three.remove(mobile.number)
        self.assertEqual([], self.three.to_list())

    def test_remove_all_no_verified(self):
        verified = self.four.verified.to_list()
        if verified:
            for mobile in verified:
                if not mobile.is_primary:
                    self.four.remove(mobile.number)
            self.four.remove(self.four.primary.number)
        for mobile in self.four.to_list():
            self.four.remove(mobile.number)
        self.assertEqual([], self.four.to_list())

    def test_unverify_all(self):
        verified = self.three.verified.to_list()
        if verified:
            self.three.primary.is_primary = False
            for mobile in verified:
                if not mobile.is_primary:
                    mobile.is_verified = False
        self.assertTrue(all([not x.is_verified for x in self.three.to_list()]))

    def test_primary(self):
        match = self.one.primary
        self.assertEqual(match.number, '+46700000001')

    def test_empty_primary(self):
        self.assertEqual(None, self.empty.primary)

    def test_set_primary_to_same(self):
        match = self.one.primary
        self.one.primary = match.number

        match = self.two.primary
        self.two.primary = match.number

    def test_set_unknown_as_primary(self):
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            self.one.primary = '+46709999999'

    def test_set_unverified_as_primary(self):
        with self.assertRaises(eduid_userdb.element.PrimaryElementViolation):
            self.three.primary = '+46700000003'

    def test_change_primary(self):
        match = self.two.primary
        self.assertEqual(match.number, '+46700000001')
        self.two.primary = '+46700000002'
        updated = self.two.primary
        self.assertEqual(updated.number, '+46700000002')

    def test_bad_input_two_primary(self):
        one = copy.deepcopy(_one_dict)
        two = copy.deepcopy(_two_dict)
        one['primary'] = True
        two['primary'] = True
        with self.assertRaises(eduid_userdb.element.PrimaryElementViolation):
            PhoneNumberList([one, two])

    def test_unverified_primary(self):
        one = copy.deepcopy(_one_dict)
        one['verified'] = False
        with self.assertRaises(eduid_userdb.element.PrimaryElementViolation):
            PhoneNumberList([one])


class TestPhoneNumber(unittest.TestCase):
    def setUp(self):
        self.empty = PhoneNumberList([])
        self.one = PhoneNumberList([_one_dict])
        self.two = PhoneNumberList([_one_dict, _two_dict])
        self.three = PhoneNumberList([_one_dict, _two_dict, _three_dict])

    def test_key(self):
        """
        Test that the 'key' property (used by PrimaryElementList) works for the PhoneNumber.
        """
        address = self.two.primary
        self.assertEqual(address.key, address.number)

    def test_create_phone_number(self):
        one = copy.deepcopy(_one_dict)
        one = PhoneNumber.from_dict(one)
        # remove added timestamp
        one_dict = one.to_dict()

        assert _one_dict['primary'] == one_dict['primary'], 'Created phone has wrong is_primary'
        assert _one_dict['verified'] == one_dict['verified'], 'Created phone has wrong is_verified'
        assert _one_dict['number'] == one_dict['number'], 'Created phone has wrong number'

    def test_parse_cycle(self):
        """
        Tests that we output something we parsed back into the same thing we output.
        """
        for this in [self.one, self.two, self.three]:
            this_dict = this.to_list_of_dicts()
            self.assertEqual(PhoneNumberList(this_dict).to_list_of_dicts(), this.to_list_of_dicts())

    def test_unknown_input_data(self):
        one = copy.deepcopy(_one_dict)
        one['foo'] = 'bar'
        with self.assertRaises(TypeError):
            PhoneNumber.from_dict(one)

    def test_changing_is_verified_on_primary(self):
        this = self.one.primary
        with self.assertRaises(eduid_userdb.element.PrimaryElementViolation):
            this.is_verified = False

    def test_changing_is_verified(self):
        this = self.three.find('+46700000003')
        this.is_verified = False  # was False already
        this.is_verified = True

    def test_verified_by(self):
        this = self.three.find('+46700000003')
        this.verified_by = 'unit test'
        self.assertEqual(this.verified_by, 'unit test')

    def test_modify_verified_by(self):
        this = self.three.find('+46700000003')
        this.verified_by = 'unit test'
        self.assertEqual(this.verified_by, 'unit test')
        this.verified_by = 'test unit'
        self.assertEqual(this.verified_by, 'test unit')

    def test_modify_verified_ts(self):
        this = self.three.find('+46700000003')
        now = datetime.datetime.utcnow()
        this.verified_ts = now
        self.assertEqual(this.verified_ts, now)

    def test_created_by(self):
        this = self.three.find('+46700000003')
        this.created_by = 'unit test'
        self.assertEqual(this.created_by, 'unit test')

    def test_created_ts(self):
        this = self.three.find('+46700000003')
        self.assertIsInstance(this.created_ts, datetime.datetime)
