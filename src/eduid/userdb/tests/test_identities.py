import datetime
import unittest
from unittest import TestCase

import pytest
from pydantic import ValidationError

import eduid.userdb.exceptions
from eduid.common.misc.timeutil import utc_now
from eduid.common.testing_base import normalised_data
from eduid.userdb import PhoneNumber
from eduid.userdb.element import ElementKey
from eduid.userdb.identity import (
    EIDASLoa,
    IdentityList,
    IdentityProofingMethod,
    IdentityType,
    NinIdentity,
    PridPersistence,
)

__author__ = "lundberg"

_one_dict = {
    "number": "197801011234",
    "verified": True,
    "identity_type": IdentityType.NIN.value,
}

_two_dict = {
    "svipe_id": "unique svipe identifier",
    "administrative_number": "administrative number 1234",
    "country_code": "DE",
    "date_of_birth": datetime.date.fromisoformat("2000-01-01"),
    "verified": True,
    "identity_type": IdentityType.SVIPE.value,
}

_three_dict = {
    "prid": "unique prid",
    "prid_persistence": PridPersistence.A.value,
    "loa": EIDASLoa.NF_SUBSTANTIAL,
    "country_code": "DE",
    "date_of_birth": datetime.date.fromisoformat("2000-01-01"),
    "verified": False,
    "identity_type": IdentityType.EIDAS.value,
}


class TestIdentityList(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None  # Make pytest show full diffs
        self.empty = IdentityList()
        self.one = IdentityList.from_list_of_dicts([_one_dict])
        self.two = IdentityList.from_list_of_dicts([_one_dict, _two_dict])
        self.three = IdentityList.from_list_of_dicts([_one_dict, _two_dict, _three_dict])

    def test_init_bad_data(self):
        with pytest.raises(ValidationError):
            IdentityList(elements="bad input data")
        with pytest.raises(ValidationError):
            IdentityList(elements=["bad input data"])

    def test_to_list(self):
        self.assertEqual([], self.empty.to_list(), list)
        self.assertIsInstance(self.one.to_list(), list)

        self.assertEqual(1, len(self.one.to_list()))

    def test_to_list_of_dicts(self):
        self.assertEqual([], self.empty.to_list_of_dicts(), list)

    def test_find(self):
        match = self.one.find("nin")
        self.assertIsInstance(match, NinIdentity)
        self.assertEqual(match.number, "197801011234")
        assert match.is_verified is True
        assert match.verified_ts is None

    def test_add(self):
        second = self.two.find("svipe")
        self.one.add(second)

        expected = self.two.to_list_of_dicts()
        obtained = self.one.to_list_of_dicts()

        assert normalised_data(obtained) == normalised_data(expected), "List with removed NIN has unexpected data"

    def test_add_duplicate(self) -> None:
        assert isinstance(self.two, IdentityList)
        assert self.two.nin is not None
        dup = self.two.find(self.two.nin.key)
        assert dup is not None
        with pytest.raises(ValidationError) as exc_info:
            self.two.add(dup)

        assert normalised_data(exc_info.value.errors(), exclude_keys=["input", "url"]) == normalised_data(
            [
                {
                    "ctx": {"error": ValueError("Duplicate element key: <IdentityType.NIN: 'nin'>")},
                    "loc": ("elements",),
                    "msg": "Value error, Duplicate element key: <IdentityType.NIN: 'nin'>",
                    "type": "value_error",
                }
            ],
        ), f"Wrong error message: {normalised_data(exc_info.value.errors(), exclude_keys=['input', 'url'])}"

    def test_add_nin(self):
        third = self.three.find("eidas")
        this = IdentityList.from_list_of_dicts([_one_dict, _two_dict, third.to_dict()])

        expected = self.three.to_list_of_dicts()
        obtained = this.to_list_of_dicts()

        assert normalised_data(obtained) == normalised_data(expected), "List with added nin has unexpected data"

    def test_add_wrong_type(self):
        """Test adding a phone number to the nin-list.
        Specifically phone, since pydantic can coerce it into a nin since they both have the 'number' field.
        """
        new = PhoneNumber(number="+4612345678")
        with pytest.raises(ValidationError) as exc_info:
            self.one.add(new)
        assert normalised_data(exc_info.value.errors(), exclude_keys=["input", "url"]) == normalised_data(
            [
                {
                    "ctx": {"class_name": "IdentityElement"},
                    "loc": ("elements", 1),
                    "msg": "Input should be a valid dictionary or instance of IdentityElement",
                    "type": "model_type",
                }
            ],
        ), f"Wrong error message: {normalised_data(exc_info.value.errors(), exclude_keys=['input', 'url'])}"

    def test_remove(self):
        self.three.remove(ElementKey("eidas"))
        now_two = self.three

        expected = self.two.to_list_of_dicts()
        obtained = now_two.to_list_of_dicts()

        assert normalised_data(obtained) == normalised_data(expected), "List with removed NIN has unexpected data"

    def test_remove_unknown(self):
        with self.assertRaises(eduid.userdb.exceptions.UserDBValueError):
            self.one.remove(ElementKey("+46709999999"))


class TestIdentity(TestCase):
    def setUp(self):
        self.empty = IdentityList()
        self.one = IdentityList.from_list_of_dicts([_one_dict])
        self.two = IdentityList.from_list_of_dicts([_one_dict, _two_dict])
        self.three = IdentityList.from_list_of_dicts([_one_dict, _two_dict, _three_dict])

    def test_key(self):
        """
        Test that the 'key' property (used by PrimaryElementList) works for the Nin.
        """
        nin = self.two.nin
        self.assertEqual(IdentityType.NIN.value, nin.key)

    def test_parse_cycle(self):
        """
        Tests that we output something we parsed back into the same thing we output.
        """
        for this in [self.one, self.two, self.three]:
            this_dict = this.to_list_of_dicts()
            self.assertEqual(IdentityList.from_list_of_dicts(this_dict).to_list_of_dicts(), this.to_list_of_dicts())

    def test_changing_is_verified(self):
        this = self.three.find("nin")
        this.is_verified = False  # was False already
        this.is_verified = True

    def test_verified_by(self):
        this = self.three.find("svipe")
        this.verified_by = "unit test"
        self.assertEqual(this.verified_by, "unit test")

    def test_modify_verified_by(self):
        this = self.three.find("eidas")
        this.verified_by = "unit test"
        this.verified_by = "test unit"
        self.assertEqual(this.verified_by, "test unit")

    def test_modify_verified_ts(self):
        this = self.three.find("nin")
        now = utc_now()
        this.verified_ts = now
        self.assertEqual(this.verified_ts, now)

    def test_created_by(self):
        this = self.three.find("svipe")
        this.created_by = "unit test"
        self.assertEqual(this.created_by, "unit test")

    def test_modify_created_by(self):
        this = self.three.find("eidas")
        this.created_by = "unit test"

        assert this.created_by == "unit test"

    def test_created_ts(self):
        this = self.three.find("nin")
        self.assertIsInstance(this.created_ts, datetime.datetime)

    def test_ts_bool(self):
        # check that we can't set created_ts or modified_ts to a bool but that we
        # can read those from db to fix them
        this = self.three.find("nin")
        with self.assertRaises(ValidationError):
            this.created_ts = True
        with self.assertRaises(ValidationError):
            this.modified_ts = True
        this_dict = this.to_dict()
        this_dict["created_ts"] = True
        this_dict["modified_ts"] = True
        assert NinIdentity.from_dict(this_dict) is not None

    def test_get_missing_proofing_method(self):
        this = self.three.find("nin")
        this.verified_by = "foo"
        assert this.get_missing_proofing_method() is None
        this.verified_by = "bankid"
        assert this.get_missing_proofing_method() is IdentityProofingMethod.BANKID
        this.verified_by = "eidas"
        assert this.get_missing_proofing_method() is IdentityProofingMethod.SWEDEN_CONNECT
        this.verified_by = "eduid-eidas"
        assert this.get_missing_proofing_method() is IdentityProofingMethod.SWEDEN_CONNECT
        this.verified_by = "eduid-idproofing-letter"
        assert this.get_missing_proofing_method() is IdentityProofingMethod.LETTER
        this.verified_by = "lookup_mobile_proofing"
        assert this.get_missing_proofing_method() is IdentityProofingMethod.TELEADRESS
        this.verified_by = "oidc_proofing"
        assert this.get_missing_proofing_method() is IdentityProofingMethod.SE_LEG
        this.verified_by = "svipe_id"
        assert this.get_missing_proofing_method() is IdentityProofingMethod.SVIPE_ID
