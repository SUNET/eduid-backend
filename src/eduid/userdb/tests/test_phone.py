import copy
import datetime
import unittest

import pytest
from pydantic import ValidationError

import eduid.userdb.element
import eduid.userdb.exceptions
from eduid.common.misc.timeutil import utc_now
from eduid.common.testing_base import normalised_data
from eduid.userdb import MailAddress
from eduid.userdb.element import ElementKey
from eduid.userdb.phone import PhoneNumber, PhoneNumberList

__author__ = "ft"

_one_dict = {
    "number": "+46700000001",
    "primary": True,
    "verified": True,
}

_two_dict = {
    "number": "+46700000002",
    "primary": False,
    "verified": True,
}

_three_dict = {
    "number": "+46700000003",
    "primary": False,
    "verified": False,
}

_four_dict = {
    "number": "+46700000004",
    "primary": False,
    "verified": False,
}


class TestPhoneNumberList(unittest.TestCase):
    def setUp(self) -> None:
        self.empty = PhoneNumberList()
        self.one = PhoneNumberList.from_list_of_dicts([_one_dict])
        self.two = PhoneNumberList.from_list_of_dicts([_one_dict, _two_dict])
        self.three = PhoneNumberList.from_list_of_dicts([_one_dict, _two_dict, _three_dict])
        self.four = PhoneNumberList.from_list_of_dicts([_three_dict, _four_dict])

    def test_init_bad_data(self) -> None:
        with pytest.raises(ValidationError):
            PhoneNumberList(elements="bad input data")
        with pytest.raises(ValidationError):
            PhoneNumberList(elements=["bad input data"])

    def test_to_list(self) -> None:
        assert self.empty.to_list_of_dicts() == []
        assert isinstance(self.one.to_list(), list)

        assert len(self.one.to_list()) == 1

    def test_to_list_of_dicts(self) -> None:
        assert self.empty.to_list_of_dicts() == []

        one_dict_list = self.one.to_list_of_dicts()
        expected = [_one_dict]

        assert one_dict_list == expected

    def test_find(self) -> None:
        match = self.one.find("+46700000001")
        assert match
        self.assertIsInstance(match, PhoneNumber)
        self.assertEqual(match.number, "+46700000001")
        self.assertEqual(match.is_verified, True)
        self.assertEqual(match.verified_ts, None)

    def test_add(self) -> None:
        second = self.two.find("+46700000002")
        assert second
        self.one.add(second)
        expected = self.two.to_list_of_dicts()
        got = self.one.to_list_of_dicts()

        assert got == expected, "Adding a phone number to a list results in wrong data"

    def test_add_duplicate(self) -> None:
        assert self.two.primary
        dup = self.two.find(self.two.primary.number)
        assert dup
        with pytest.raises(ValidationError) as exc_info:
            self.two.add(dup)

        assert normalised_data(exc_info.value.errors(), exclude_keys=["input", "url"]) == normalised_data(
            [
                {
                    "ctx": {"error": ValueError("Duplicate element key: '+46700000001'")},
                    "loc": ("elements",),
                    "msg": "Value error, Duplicate element key: '+46700000001'",
                    "type": "value_error",
                }
            ]
        ), f"Wrong error message: {normalised_data(exc_info.value.errors(), exclude_keys=['input', 'url'])}"

    def test_add_phonenumber(self) -> None:
        third = self.three.find("+46700000003")
        assert third
        this = PhoneNumberList.from_list_of_dicts([_one_dict, _two_dict, third.to_dict()])

        expected = self.three.to_list_of_dicts()
        got = this.to_list_of_dicts()

        assert got == expected, "Phone number list contains wrong data"

    def test_add_another_primary(self) -> None:
        new = PhoneNumber(number="+46700000009", is_verified=True, is_primary=True)
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            self.one.add(new)

    def test_add_wrong_type(self) -> None:
        new = MailAddress(email="ft@example.org")
        with pytest.raises(ValidationError) as exc_info:
            self.one.add(new)  # type: ignore[arg-type]
        assert normalised_data(exc_info.value.errors(), exclude_keys=["input", "url"]) == normalised_data(
            [
                {
                    "ctx": {"class_name": "PhoneNumber"},
                    "loc": ("elements", 1),
                    "msg": "Input should be a valid dictionary or instance of PhoneNumber",
                    "type": "model_type",
                }
            ]
        ), f"Wrong error message: {normalised_data(exc_info.value.errors(), exclude_keys=['input', 'url'])}"

    def test_remove(self) -> None:
        self.three.remove(ElementKey("+46700000003"))
        now_two = self.three

        expected = self.two.to_list_of_dicts()
        got = now_two.to_list_of_dicts()

        assert got == expected, "Phone list has wrong data after removing phone"

    def test_remove_unknown(self) -> None:
        with self.assertRaises(eduid.userdb.exceptions.UserDBValueError):
            self.one.remove(ElementKey("+46709999999"))

    def test_remove_primary(self) -> None:
        assert self.two.primary
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            self.two.remove(ElementKey(self.two.primary.number))

    def test_remove_primary_single(self) -> None:
        assert self.one.primary
        self.one.remove(ElementKey(self.one.primary.number))
        now_empty = self.one

        assert now_empty.to_list() == []

    def test_remove_all_mix(self) -> None:
        # First, remove all numbers except the primary
        for mobile in self.three.to_list():
            if not mobile.is_primary:
                self.three.remove(mobile.key)
        # Now, remove the primary number (which can't be removed until it is the last element)
        assert self.three.primary
        self.three.remove(self.three.primary.key)
        assert self.three.to_list() == []

    def test_remove_all_no_verified(self) -> None:
        verified = self.four.verified
        if verified:
            for mobile in verified:
                if not mobile.is_primary:
                    self.four.remove(ElementKey(mobile.number))
            assert self.four.primary
            self.four.remove(ElementKey(self.four.primary.number))
        for mobile in self.four.to_list():
            self.four.remove(ElementKey(mobile.number))
        self.assertEqual([], self.four.to_list())

    def test_unverify_all(self) -> None:
        verified = self.three.verified

        for mobile in verified:
            mobile.is_primary = False
            mobile.is_verified = False

        verified_now = self.three.verified
        assert verified_now == []

    def test_primary(self) -> None:
        match = self.one.primary
        assert match
        self.assertEqual(match.number, "+46700000001")

    def test_empty_primary(self) -> None:
        self.assertEqual(None, self.empty.primary)

    def test_set_primary_to_same(self) -> None:
        match = self.one.primary
        assert match
        self.one.set_primary(ElementKey(match.number))

        match = self.two.primary
        assert match
        self.two.set_primary(ElementKey(match.number))

    def test_set_unknown_as_primary(self) -> None:
        with self.assertRaises(eduid.userdb.exceptions.UserDBValueError):
            self.one.set_primary(ElementKey("+46709999999"))

    def test_set_unverified_as_primary(self) -> None:
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            self.three.set_primary(ElementKey("+46700000003"))

    def test_change_primary(self) -> None:
        match = self.two.primary
        assert match
        self.assertEqual(match.number, "+46700000001")
        self.two.set_primary(ElementKey("+46700000002"))
        updated = self.two.primary
        assert updated
        self.assertEqual(updated.number, "+46700000002")

    def test_bad_input_two_primary(self) -> None:
        one = copy.deepcopy(_one_dict)
        two = copy.deepcopy(_two_dict)
        one["primary"] = True
        two["primary"] = True
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            PhoneNumberList.from_list_of_dicts([one, two])

    def test_unverified_primary(self) -> None:
        one = copy.deepcopy(_one_dict)
        one["verified"] = False
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            PhoneNumberList.from_list_of_dicts([one])


class TestPhoneNumber(unittest.TestCase):
    def setUp(self) -> None:
        self.empty = PhoneNumberList()
        self.one = PhoneNumberList.from_list_of_dicts([_one_dict])
        self.two = PhoneNumberList.from_list_of_dicts([_one_dict, _two_dict])
        self.three = PhoneNumberList.from_list_of_dicts([_one_dict, _two_dict, _three_dict])

    def test_key(self) -> None:
        """
        Test that the 'key' property (used by PrimaryElementList) works for the PhoneNumber.
        """
        address = self.two.primary
        assert address
        self.assertEqual(address.key, address.number)

    def test_create_phone_number(self) -> None:
        one_copy = copy.deepcopy(_one_dict)
        one = PhoneNumber.from_dict(one_copy)
        # remove added timestamp
        one_dict = one.to_dict()

        assert _one_dict["primary"] == one_dict["primary"], "Created phone has wrong is_primary"
        assert _one_dict["verified"] == one_dict["verified"], "Created phone has wrong is_verified"
        assert _one_dict["number"] == one_dict["number"], "Created phone has wrong number"

    def test_parse_cycle(self) -> None:
        """
        Tests that we output something we parsed back into the same thing we output.
        """
        for this in [self.one, self.two, self.three]:
            this_dict = this.to_list_of_dicts()
            self.assertEqual(PhoneNumberList.from_list_of_dicts(this_dict).to_list_of_dicts(), this.to_list_of_dicts())

    def test_unknown_input_data(self) -> None:
        one = copy.deepcopy(_one_dict)
        one["foo"] = "bar"
        with pytest.raises(ValidationError) as exc_info:
            PhoneNumber.from_dict(one)

        assert normalised_data(exc_info.value.errors(), exclude_keys=["url"]) == [
            {
                "input": "bar",
                "loc": ["foo"],
                "msg": "Extra inputs are not permitted",
                "type": "extra_forbidden",
            }
        ], f"Wrong error message: {normalised_data(exc_info.value.errors(), exclude_keys=['url'])}"

    def test_changing_is_verified_on_primary(self) -> None:
        this = self.one.primary
        assert this
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            this.is_verified = False

    def test_changing_is_verified(self) -> None:
        this = self.three.find("+46700000003")
        assert this
        this.is_verified = False  # was False already
        this.is_verified = True

    def test_verified_by(self) -> None:
        this = self.three.find("+46700000003")
        assert this
        this.verified_by = "unit test"
        self.assertEqual(this.verified_by, "unit test")

    def test_modify_verified_by(self) -> None:
        this = self.three.find("+46700000003")
        assert this
        this.verified_by = "unit test"
        self.assertEqual(this.verified_by, "unit test")
        this.verified_by = "test unit"
        self.assertEqual(this.verified_by, "test unit")

    def test_modify_verified_ts(self) -> None:
        this = self.three.find("+46700000003")
        assert this
        now = utc_now()
        this.verified_ts = now
        self.assertEqual(this.verified_ts, now)

    def test_created_by(self) -> None:
        this = self.three.find("+46700000003")
        assert this
        this.created_by = "unit test"
        self.assertEqual(this.created_by, "unit test")

    def test_created_ts(self) -> None:
        this = self.three.find("+46700000003")
        assert this
        self.assertIsInstance(this.created_ts, datetime.datetime)
