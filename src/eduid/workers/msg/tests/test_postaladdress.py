__author__ = "lundberg"

import json
from pathlib import PurePath
from unittest import TestCase

from eduid.workers.msg import utils


class TestPostalAddress(TestCase):
    def setUp(self) -> None:
        self.navet_data = json.load(open(PurePath(__file__).with_name("data") / "navet.json"))
        self.navet_data_unregistered = json.load(open(PurePath(__file__).with_name("data") / "navet_unregistered.json"))

    def test_get_all_data_dict(self) -> None:
        result = utils.navet_get_all_data(self.navet_data)
        assert result
        assert result["Person"]["Name"]["GivenName"] == "Saskariot Teofil"
        assert (
            result["Person"]["PostalAddresses"]["OfficialAddress"]["Address2"] == "MALMSKILLNADSGATAN 54 25 TR LÄG 458"
        )
        assert result["Person"]["Relations"][0]["RelationId"]["NationalIdentityNumber"] == "196910199287"
        assert result["Person"]["Relations"][0]["RelationType"] == "M"

    def test_get_name_and_official_address(self) -> None:
        result = utils.navet_get_name_and_official_address(self.navet_data)
        assert result
        self.assertEqual(result["Name"]["GivenName"], "Saskariot Teofil")
        self.assertEqual(result["OfficialAddress"]["Address2"], "MALMSKILLNADSGATAN 54 25 TR LÄG 458")

    def test_get_relations(self) -> None:
        result = utils.navet_get_relations(self.navet_data)
        assert result
        self.assertEqual(result["Relations"]["Relation"][0]["RelationId"]["NationalIdentityNumber"], "196910199287")
        self.assertEqual(result["Relations"]["Relation"][0]["RelationType"], "M")

    def test_get_unregistered_all_data(self) -> None:
        result = utils.navet_get_all_data(self.navet_data_unregistered)
        assert result
        assert result["Person"]["DeregistrationInformation"]["date"] == "20220315"
        assert result["Person"]["DeregistrationInformation"]["causeCode"] == "AV"
        assert result["Person"]["Name"]["GivenName"] == "Saskariot Teofil"
        assert (
            result["Person"]["PostalAddresses"]["OfficialAddress"]["Address2"] == "MALMSKILLNADSGATAN 54 25 TR LÄG 458"
        )
        assert result["Person"]["Relations"][0]["RelationId"]["NationalIdentityNumber"] == "196910199287"
        assert result["Person"]["Relations"][0]["RelationType"] == "M"

    def test_get_unregistered_name_and_official_address(self) -> None:
        result = utils.navet_get_name_and_official_address(self.navet_data_unregistered)
        assert result is None

    def test_get_unregistered_relations(self) -> None:
        result = utils.navet_get_relations(self.navet_data_unregistered)
        assert result is None
