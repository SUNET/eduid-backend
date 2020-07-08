import copy
import datetime
from unittest import TestCase

import eduid_userdb.element
import eduid_userdb.exceptions
from eduid_userdb.element import Element
from eduid_userdb.nin import Nin, NinList
from eduid_userdb.tests import DictTestCase

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


class TestNinList(DictTestCase):
    def setUp(self):
        self.maxDiff = None  # Make pytest show full diffs
        self.empty = NinList([])
        self.one = NinList([_one_dict])
        self.two = NinList([_one_dict, _two_dict])
        self.three = NinList([_one_dict, _two_dict, _three_dict])

    def test_init_bad_data(self):
        with self.assertRaises(eduid_userdb.element.UserDBValueError):
            NinList('bad input data')

    def test_to_list(self):
        self.assertEqual([], self.empty.to_list(), list)
        self.assertIsInstance(self.one.to_list(), list)

        self.assertEqual(1, len(self.one.to_list()))

    def test_to_list_of_dicts(self):
        self.assertEqual([], self.empty.to_list_of_dicts(), list)

        expected = [_one_dict]
        obtained = self.one.to_list_of_dicts()

        expected, obtained = self.remove_timestamps(expected, obtained)

        assert expected == obtained, 'List of one NIN has unexpected data'

    def test_find(self):
        match = self.one.find('197801011234')
        self.assertIsInstance(match, Nin)
        self.assertEqual(match.number, '197801011234')
        self.assertEqual(match.is_verified, True)
        self.assertEqual(match.verified_ts, None)

    def test_add(self):
        second = self.two.find('197802022345')
        self.one.add(second)

        expected = self.two.to_list_of_dicts()
        got = self.one.to_list_of_dicts()
        # remove timestamps added at different times
        for d in expected:
            del d['created_ts']
        for d in got:
            if 'created_ts' in d:
                del d['created_ts']

        assert expected == got, 'List with removed NIN has unexpected data'

    def test_add_duplicate(self):
        dup = self.two.find(self.two.primary.number)
        with self.assertRaises(eduid_userdb.element.DuplicateElementViolation):
            self.two.add(dup)

    def test_add_mailaddress(self):
        third = self.three.find('197803033456')
        this = NinList([_one_dict, _two_dict, third])

        expected = self.three.to_list_of_dicts()
        got = this.to_list_of_dicts()
        # remove added timestamp
        for d in expected:
            del d['created_ts']
        for d in got:
            if 'created_ts' in d:
                del d['created_ts']

        assert expected == got, 'List with added mail address has unexpected data'

    def test_add_another_primary(self):
        new = eduid_userdb.nin.nin_from_dict({'number': '+46700000009', 'verified': True, 'primary': True,})
        with self.assertRaises(eduid_userdb.element.PrimaryElementViolation):
            self.one.add(new)

    def test_add_wrong_type(self):
        elemdict = {
            'created_by': 'tests',
        }
        new = Element.from_dict(elemdict)
        with self.assertRaises(eduid_userdb.element.UserDBValueError):
            self.one.add(new)

    def test_remove(self):
        now_two = self.three.remove('197803033456')

        expected = self.two.to_list_of_dicts()
        got = now_two.to_list_of_dicts()
        # remove timestamps added at different times
        for d in expected:
            del d['created_ts']
        for d in got:
            del d['created_ts']

        assert expected == got, 'List with removed NIN has unexpected data'

    def test_remove_unknown(self):
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            self.one.remove('+46709999999')

    def test_remove_primary(self):
        with self.assertRaises(eduid_userdb.element.PrimaryElementViolation):
            self.two.remove(self.two.primary.number)

    def test_remove_primary_single(self):
        now_empty = self.one.remove(self.one.primary.number)
        self.assertEqual([], now_empty.to_list())

    def test_primary(self):
        match = self.one.primary
        self.assertEqual(match.number, '197801011234')

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
            self.three.primary = '197803033456'

    def test_change_primary(self):
        match = self.two.primary
        self.assertEqual(match.number, '197801011234')
        self.two.primary = '197802022345'
        updated = self.two.primary
        self.assertEqual(updated.number, '197802022345')

    def test_bad_input_two_primary(self):
        one = copy.deepcopy(_one_dict)
        two = copy.deepcopy(_two_dict)
        one['primary'] = True
        two['primary'] = True
        with self.assertRaises(eduid_userdb.element.PrimaryElementViolation):
            NinList([one, two])

    def test_bad_input_unverified_primary(self):
        one = copy.deepcopy(_one_dict)
        one['verified'] = False
        with self.assertRaises(eduid_userdb.element.PrimaryElementViolation):
            this = NinList([one])


class TestNin(TestCase):
    def setUp(self):
        self.empty = NinList([])
        self.one = NinList([_one_dict])
        self.two = NinList([_one_dict, _two_dict])
        self.three = NinList([_one_dict, _two_dict, _three_dict])

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
            self.assertEqual(NinList(this_dict).to_list_of_dicts(), this.to_list_of_dicts())

    def test_changing_is_verified_on_primary(self):
        this = self.one.primary
        with self.assertRaises(eduid_userdb.element.PrimaryElementViolation):
            this.is_verified = False

    def test_changing_is_verified(self):
        this = self.three.find('197803033456')
        this.is_verified = False  # was False already
        this.is_verified = True

    def test_verified_by(self):
        this = self.three.find('197803033456')
        this.verified_by = 'unit test'
        self.assertEqual(this.verified_by, 'unit test')

    def test_modify_verified_by(self):
        this = self.three.find('197803033456')
        this.verified_by = 'unit test'
        this.verified_by = 'test unit'
        self.assertEqual(this.verified_by, 'test unit')

    def test_modify_verified_ts(self):
        this = self.three.find('197803033456')
        now = datetime.datetime.utcnow()
        this.verified_ts = now
        self.assertEqual(this.verified_ts, now)

    def test_created_by(self):
        this = self.three.find('197803033456')
        this.created_by = 'unit test'
        self.assertEqual(this.created_by, 'unit test')

    def test_modify_created_by(self):
        this = self.three.find('197803033456')
        this.created_by = 'unit test'

        assert this.created_by == 'unit test'

    def test_created_ts(self):
        this = self.three.find('197803033456')
        self.assertIsInstance(this.created_ts, datetime.datetime)
