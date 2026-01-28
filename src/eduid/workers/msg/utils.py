"""
This module provides utility functions.
"""

import os
from collections import OrderedDict
from collections.abc import Mapping
from typing import Any


def is_deregistered(person: dict[str, Any] | None) -> bool:
    if person is None:
        return False
    deregistration_information = person["DeregistrationInformation"]
    return bool(deregistration_information.get("date") or deregistration_information.get("causeCode"))


def load_template(template_dir: str, filename: str, message_dict: Mapping[str, str], lang: str) -> str:
    """
    This function loads a template file by provided language.
    """
    from jinja2 import Environment, FileSystemLoader

    if os.path.isdir(template_dir):
        try:
            f = f"{filename}.{lang}"
            if os.path.exists(os.path.join(template_dir, f)):
                filename = f
            template = Environment(loader=FileSystemLoader(template_dir)).get_template(filename)
            return template.render(message_dict)
        except OSError:
            pass
    raise RuntimeError("template not found")


def navet_get_name_and_official_address(navet_data: dict[str, Any] | None) -> OrderedDict[str, Any] | None:
    """
    :param navet_data:  Loaded JSON response from eduid-navet_service
    :return: Name and official address data objects
    """
    person = navet_get_person(navet_data)
    if is_deregistered(person):
        return None

    if person is not None:
        try:
            return OrderedDict(
                [("Name", person["Name"]), ("OfficialAddress", person["PostalAddresses"]["OfficialAddress"])]
            )
        except KeyError:
            pass
    return None


def navet_get_relations(navet_data: dict[str, Any] | None) -> OrderedDict[str, Any] | None:
    """
    :param navet_data:  Loaded JSON response from eduid-navet_service
    :return: Relations data object
    """
    person = navet_get_person(navet_data)
    if is_deregistered(person):
        return None

    if person is not None:
        try:
            return OrderedDict([("Relations", {"Relation": person["Relations"]})])
        except KeyError:
            pass
    return None


def navet_get_person(navet_data: dict[str, Any] | None) -> OrderedDict[str, Any] | None:
    """
    :param navet_data: Loaded JSON response from eduid-navet_service
    :return: Personpost
    {
        "Name": {
        "GivenName": "Saskariot Teofil",
        "Surname": "Nor\u00e9n"
        },
        "PersonId": {
            "NationalIdentityNumber": "197609272393"
        },
        "ReferenceNationalIdentityNumber": "",
        "PostalAddresses": {
            "OfficialAddress": {
                "Address1": "\u00d6VER G\u00c5RDEN",
                "Address2": "MALMSKILLNADSGATAN 54 25 TR L\u00c4G 458",
                "CareOf": "MALMSTR\u00d6M",
                "City": "STOCKHOLM",
                "PostalCode": "11138"
            }
        },
        "Relations": [
            {
                "RelationId": {
                    "NationalIdentityNumber": "196910199287"
                },
                "RelationType": "M"
            }
        ]
    }
    """
    if navet_data is not None:
        try:
            return OrderedDict(navet_data["PopulationItems"][0]["PersonItem"])
        except KeyError:
            pass
    return None


def navet_get_all_data(navet_data: dict[str, Any] | None) -> OrderedDict[str, Any] | None:
    """
    :param navet_data: Loaded JSON response from eduid-navet_service
    :return: all available data from Navet

    {
        "CaseInformation": {"lastChanged": "20170904141659"},
        "Person": {
            "Name": {"GivenName": "Saskariot Teofil", "Surname": "Nor\u00e9n"},
            "PersonId": {"NationalIdentityNumber": "197609272393"},
            "ReferenceNationalIdentityNumber": "",
            "DeregistrationInformation": {},
            "PostalAddresses": {
                "OfficialAddress": {
                    "Address1": "\u00d6VER G\u00c5RDEN",
                    "Address2": "MALMSKILLNADSGATAN 54 25 TR L\u00c4G 458",
                    "CareOf": "MALMSTR\u00d6M",
                    "City": "STOCKHOLM",
                    "PostalCode": "11138",
                }
            },
            "Relations": [{"RelationId": {"NationalIdentityNumber": "196910199287"}, "RelationType": "M"}],
        },
    }
    """
    person = navet_get_person(navet_data)
    if navet_data is not None and person is not None:
        try:
            case_information = OrderedDict(navet_data["PopulationItems"][0]["CaseInformation"])
            return OrderedDict({"CaseInformation": case_information, "Person": person})
        except KeyError:
            pass
    return None
