# -*- encoding: utf-8 -*-
"""
This module provides utility functions.
"""

import os
from collections import OrderedDict
from typing import Optional


def load_template(template_dir: str, filename: str, message_dict: dict, lang: str) -> str:
    """
    This function loads a template file by provided language.
    """
    from jinja2 import Environment, FileSystemLoader

    if isinstance(template_dir, str) and os.path.isdir(template_dir):
        try:
            f = '.'.join([filename, lang])
            if os.path.exists(os.path.join(template_dir, f)):
                filename = f
            template = Environment(loader=FileSystemLoader(template_dir)).get_template(filename)
            return template.render(message_dict)
        except OSError:
            pass
    raise RuntimeError("template not found")


def navet_get_name(navet_data: dict) -> Optional[OrderedDict]:
    """
    :param navet_data: Loaded JSON response from eduid-navet_service
    :return: Name data object
    """
    person = navet_get_person(navet_data)
    if person is not None:
        try:
            return OrderedDict([(u'Name', person['Name']),])
        except KeyError:
            pass
    return None


def navet_get_official_address(navet_data: dict) -> Optional[OrderedDict]:
    """
    :param navet_data:  Loaded JSON response from eduid-navet_service
    :return: Official address data object
    """
    person = navet_get_person(navet_data)
    if person is not None:
        try:
            return OrderedDict([(u'OfficialAddress', person['PostalAddresses']['OfficialAddress']),])
        except KeyError:
            pass
    return None


def navet_get_name_and_official_address(navet_data: Optional[dict]) -> Optional[OrderedDict]:
    """
    :param navet_data:  Loaded JSON response from eduid-navet_service
    :return: Name and official address data objects
    """
    person = navet_get_person(navet_data)
    if person is not None:
        try:
            return OrderedDict(
                [(u'Name', person['Name']), (u'OfficialAddress', person['PostalAddresses']['OfficialAddress']),]
            )
        except KeyError:
            pass
    return None


def navet_get_relations(navet_data: Optional[dict]) -> Optional[OrderedDict]:
    """
    :param navet_data:  Loaded JSON response from eduid-navet_service
    :return: Relations data object
    """
    person = navet_get_person(navet_data)
    if person is not None:
        try:
            return OrderedDict([('Relations', {'Relation': person['Relations']}),])
        except KeyError:
            pass
    return None


def navet_get_person(navet_data: Optional[dict]) -> Optional[OrderedDict]:
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
            return OrderedDict(navet_data['PopulationItems'][0]['PersonItem'])
        except KeyError:
            pass
    return None


def navet_get_all_data(navet_data: Optional[dict]) -> Optional[OrderedDict]:
    """
    :param navet_data: Loaded JSON response from eduid-navet_service
    :return: all available data from Navet

    {
        "CaseInformation": {"lastChanged": "20170904141659"},
        "Person": {
            "Name": {"GivenName": "Saskariot Teofil", "Surname": "Nor\u00e9n"},
            "PersonId": {"NationalIdentityNumber": "197609272393"},
            "ReferenceNationalIdentityNumber": "",
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
            case_information = OrderedDict(navet_data['PopulationItems'][0]['CaseInformation'])
            return OrderedDict({"CaseInformation": case_information, "Person": person})
        except KeyError:
            pass
    return None
