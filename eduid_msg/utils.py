# -*- encoding: utf-8 -*-
"""
This module provides utility functions.
"""

import six
import os
from collections import OrderedDict


def load_template(template_dir, filename, message_dict, lang):
    """
    This function loads a template file by provided language.
    """
    from jinja2 import Environment, FileSystemLoader

    if not isinstance(template_dir, six.string_types):
        return False
    if not os.path.isdir(template_dir):
        return False
    try:
        f = '.'.join([filename, lang])
        if os.path.exists(os.path.join(template_dir, f)):
            filename = f
        template = Environment(loader=FileSystemLoader(template_dir)).get_template(filename)
        return template.render(message_dict)
    except OSError:
        return False


def navet_get_name(navet_data):
    """
    :param navet_data: Loaded JSON response from eduid-navet_service
    :type navet_data: dict
    :return: Name data object
    :rtype: OrderedDict|None
    """
    try:
        person = navet_get_person(navet_data)
        result = OrderedDict([(u'Name', person['Name']), ])
    except (KeyError, TypeError):
        result = None
    return result


def navet_get_official_address(navet_data):
    """
    :param navet_data:  Loaded JSON response from eduid-navet_service
    :type navet_data: dict
    :return: Official address data object
    :rtype: OrderedDict|None
    """
    try:
        person = navet_get_person(navet_data)
        result = OrderedDict([(u'OfficialAddress', person['PostalAddresses']['OfficialAddress']), ])
    except (KeyError, TypeError):
        result = None
    return result


def navet_get_name_and_official_address(navet_data):
    """
    :param navet_data:  Loaded JSON response from eduid-navet_service
    :type navet_data: dict
    :return: Name and official address data objects
    :rtype: OrderedDict|None
    """
    try:
        person = navet_get_person(navet_data)
        result = OrderedDict([(u'Name', person['Name']),
                              (u'OfficialAddress', person['PostalAddresses']['OfficialAddress']),
                              ])
    except (KeyError, TypeError):
        result = None
    return result


def navet_get_relations(navet_data):
    """
    :param navet_data:  Loaded JSON response from eduid-navet_service
    :type navet_data: dict
    :return: Relations data object
    :rtype: OrderedDict|None
    """
    try:
        person = navet_get_person(navet_data)
        result = OrderedDict([(u'Relations', {u'Relation': person['Relations']}), ])
    except (KeyError, TypeError):
        result = None
    return result


def navet_get_person(navet_data):
    """
    :param navet_data: Loaded JSON response from eduid-navet_service
    :type navet_data: dict
    :return: Personpost
    {
        "Name": {
        "GivenName": "Saskariot Teofil",
        "Surname": "Nor\u00e9n"
        },
        "PersonId": {
            "NationalIdentityNumber": "197609272393"
        },
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
    :rtype: OrderedDict
    """
    try:
        result = OrderedDict(navet_data['PopulationItems'][0]['PersonItem'])
    except (KeyError, TypeError):
        result = None
    return result
