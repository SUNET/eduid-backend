import copy
import datetime
import unittest
from unittest import TestCase

import pytest
from pydantic import ValidationError

import eduid.userdb.element
import eduid.userdb.exceptions
from eduid.common.misc.timeutil import utc_now
from eduid.common.testing_base import normalised_data
from eduid.userdb import PhoneNumber
from eduid.userdb.element import ElementKey
from eduid.userdb.mail import MailAddress, MailAddressList

__author__ = "ft"

_one_dict = {
    "email": "ft@one.example.org",
    "primary": True,
    "verified": True,
}

_two_dict = {
    "email": "ft@two.example.org",
    "primary": False,
    "verified": True,
}

_three_dict = {
    "email": "ft@three.example.org",
    "primary": False,
    "verified": False,
}


class TestMailAddressList(unittest.TestCase):
    def setUp(self) -> None:
        self.maxDiff = None
        self.empty = MailAddressList()
        self.one = MailAddressList.from_list_of_dicts([_one_dict])
        self.two = MailAddressList.from_list_of_dicts([_one_dict, _two_dict])
        self.three = MailAddressList.from_list_of_dicts([_one_dict, _two_dict, _three_dict])

    def test_init_bad_data(self) -> None:
        with pytest.raises(ValidationError):
            MailAddressList(elements="bad input data")
        with pytest.raises(ValidationError):
            MailAddressList(elements=["bad input data"])

    def test_to_list(self) -> None:
        self.assertEqual([], self.empty.to_list(), list)
        self.assertIsInstance(self.one.to_list(), list)

        self.assertEqual(1, len(self.one.to_list()))

    def test_empty_to_list_of_dicts(self) -> None:
        self.assertEqual([], self.empty.to_list_of_dicts(), list)

    def test_find(self) -> None:
        match = self.one.find("ft@one.example.org")
        assert match
        self.assertIsInstance(match, MailAddress)
        self.assertEqual(match.email, "ft@one.example.org")
        self.assertEqual(match.is_verified, True)
        self.assertEqual(match.verified_ts, None)

    def test_add(self) -> None:
        second = self.two.find("ft@two.example.org")
        assert second
        self.one.add(second)

        expected = self.two.to_list_of_dicts()
        obtained = self.one.to_list_of_dicts()

        assert obtained == expected, "Wrong data after adding mail address to list"

    def test_add_duplicate(self) -> None:
        assert self.two.primary
        dup = self.two.find(self.two.primary.email)
        assert dup
        with pytest.raises(ValidationError) as exc_info:
            self.two.add(dup)

        assert normalised_data(exc_info.value.errors(), exclude_keys=["input", "url"]) == normalised_data(
            [
                {
                    "ctx": {"error": ValueError("Duplicate element key: 'ft@one.example.org'")},
                    "loc": ("elements",),
                    "msg": "Value error, Duplicate element key: 'ft@one.example.org'",
                    "type": "value_error",
                }
            ],
        ), f"Wrong error message: {normalised_data(exc_info.value.errors(), exclude_keys=['input', 'url'])}"

    def test_add_mailaddress(self) -> None:
        third = self.three.find("ft@three.example.org")
        assert third
        this = MailAddressList.from_list_of_dicts([_one_dict, _two_dict, third.to_dict()])

        expected = self.three.to_list_of_dicts()
        obtained = this.to_list_of_dicts()

        assert obtained == expected, "Wrong data in mail address list"

    def test_add_another_primary(self) -> None:
        new = eduid.userdb.mail.address_from_dict(
            {"email": "ft@primary.example.org", "verified": True, "primary": True}
        )
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            self.one.add(new)

    def test_add_wrong_type(self) -> None:
        new = PhoneNumber(number="+4612345678")
        with pytest.raises(ValidationError):
            self.one.add(new)  # type: ignore[arg-type]

    def test_remove(self) -> None:
        self.three.remove(ElementKey("ft@three.example.org"))
        now_two = self.three

        expected = self.two.to_list_of_dicts()
        obtained = now_two.to_list_of_dicts()

        assert obtained == expected, "Wrong data after removing email from list"

    def test_remove_unknown(self) -> None:
        with self.assertRaises(eduid.userdb.exceptions.UserDBValueError):
            self.one.remove(ElementKey("foo@no-such-address.example.org"))

    def test_remove_primary(self) -> None:
        assert self.two.primary
        with pytest.raises(
            eduid.userdb.element.PrimaryElementViolation, match="Removing the primary element is not allowed"
        ):
            self.two.remove(self.two.primary.key)

    def test_remove_primary_single(self) -> None:
        assert self.one.primary
        self.one.remove(ElementKey(self.one.primary.email))
        now_empty = self.one
        self.assertEqual([], now_empty.to_list())

    def test_primary(self) -> None:
        match = self.one.primary
        assert match
        self.assertEqual(match.email, "ft@one.example.org")

    def test_empty_primary(self) -> None:
        self.assertEqual(None, self.empty.primary)

    def test_set_primary_to_same(self) -> None:
        match = self.one.primary
        assert match
        self.one.set_primary(ElementKey(match.email))

        match = self.two.primary
        assert match
        self.two.set_primary(ElementKey(match.email))

    def test_set_unknown_as_primary(self) -> None:
        with self.assertRaises(eduid.userdb.exceptions.UserDBValueError):
            self.one.set_primary(ElementKey("foo@no-such-address.example.org"))

    def test_set_unverified_as_primary(self) -> None:
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            self.three.set_primary(ElementKey("ft@three.example.org"))

    def test_change_primary(self) -> None:
        match = self.two.primary
        assert match
        self.assertEqual(match.email, "ft@one.example.org")
        self.two.set_primary(ElementKey("ft@two.example.org"))
        updated = self.two.primary
        assert updated
        self.assertEqual(updated.email, "ft@two.example.org")

    def test_bad_input_two_primary(self) -> None:
        one = copy.deepcopy(_one_dict)
        two = copy.deepcopy(_two_dict)
        one["primary"] = True
        two["primary"] = True
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            MailAddressList.from_list_of_dicts([one, two])

    def test_bad_input_unverified_primary(self) -> None:
        one = copy.deepcopy(_one_dict)
        one["verified"] = False
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            MailAddressList.from_list_of_dicts([one])


class TestMailAddress(TestCase):
    def setUp(self) -> None:
        self.empty = MailAddressList()
        self.one = MailAddressList.from_list_of_dicts([_one_dict])
        self.two = MailAddressList.from_list_of_dicts([_one_dict, _two_dict])
        self.three = MailAddressList.from_list_of_dicts([_one_dict, _two_dict, _three_dict])

    def test_key(self) -> None:
        """
        Test that the 'key' property (used by PrimaryElementList) works for the MailAddress.
        """
        address = self.two.primary
        assert address
        self.assertEqual(address.key, address.email)

    def test_parse_cycle(self) -> None:
        """
        Tests that we output something we parsed back into the same thing we output.
        """
        for this in [self.one, self.two, self.three]:
            this_list = this.to_list_of_dicts()

            expected = this.to_list_of_dicts()
            cycled = MailAddressList.from_list_of_dicts(this_list).to_list_of_dicts()

            assert cycled == expected

    def test_unknown_input_data(self) -> None:
        one = copy.deepcopy(_one_dict)
        one["foo"] = "bar"
        with pytest.raises(ValidationError) as exc_info:
            MailAddress.from_dict(one)

        assert normalised_data(exc_info.value.errors(), exclude_keys=["url"]) == [
            {
                "input": "bar",
                "loc": ["foo"],
                "msg": "Extra inputs are not permitted",
                "type": "extra_forbidden",
            }
        ], f"Wrong error message: {normalised_data(exc_info.value.errors(), exclude_keys=['url'])}"

    def test_bad_input_type(self) -> None:
        one = copy.deepcopy(_one_dict)
        one["email"] = False
        with pytest.raises(ValidationError) as exc_info:
            MailAddress.from_dict(one)

        assert normalised_data(exc_info.value.errors(), exclude_keys=["url"]) == normalised_data(
            [
                {
                    "ctx": {"error": ValueError("must be a string")},
                    "input": False,
                    "loc": ("email",),
                    "msg": "Value error, must be a string",
                    "type": "value_error",
                }
            ]
        ), f"Wrong error message: {exc_info.value.errors()}"

    def test_changing_is_verified_on_primary(self) -> None:
        this = self.one.primary
        assert this
        with self.assertRaises(eduid.userdb.element.PrimaryElementViolation):
            this.is_verified = False

    def test_changing_is_verified(self) -> None:
        this = self.three.find("ft@three.example.org")
        assert this
        this.is_verified = False  # was False already
        this.is_verified = True

    def test_verified_by(self) -> None:
        this = self.three.find("ft@three.example.org")
        assert this
        this.verified_by = "unit test"
        self.assertEqual(this.verified_by, "unit test")

    def test_modify_verified_by(self) -> None:
        this = self.three.find("ft@three.example.org")
        assert this
        this.verified_by = "unit test"
        this.verified_by = "test unit"
        self.assertEqual(this.verified_by, "test unit")

    def test_verified_ts(self) -> None:
        this = self.three.find("ft@three.example.org")
        assert this
        this.verified_ts = utc_now()
        self.assertIsInstance(this.verified_ts, datetime.datetime)

    def test_modify_verified_ts(self) -> None:
        this = self.three.find("ft@three.example.org")
        assert this
        this.verified_ts = utc_now()

    def test_created_by(self) -> None:
        this = self.three.find("ft@three.example.org")
        assert this
        this.created_by = "unit test"
        self.assertEqual(this.created_by, "unit test")

    def test_created_ts(self) -> None:
        this = self.three.find("ft@three.example.org")
        assert this
        self.assertIsInstance(this.created_ts, datetime.datetime)

    def test_uppercase_email_address(self) -> None:
        address = "UPPERCASE@example.com"
        mail_address = MailAddress(email=address)
        self.assertEqual(address.lower(), mail_address.email)
