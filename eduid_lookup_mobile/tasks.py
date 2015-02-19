from __future__ import absolute_import
from eduid_lookup_mobile.celery import app
from eduid_lookup_mobile.client import mobile_lookup_client

@app.task
def verify_by_mobile(mobile_number, national_identity_number):
    """
    Does a lookup to see if the given mobile number is registered to the person with the given national identity number.
    Uses the NIN as the key in the lookup.
    :param mobile_number: A mobile number with country code
    :param social_security_number:
    :return: true if the mobile_number was registered to the nin, else false
    """
    return mobile_lookup_client.verify_by_NIN(mobile_number, national_identity_number)

@app.task
def find_mobiles_by_NIN(national_identity_number, number_region=None):
    """
    Searches mobile numbers registered to the given nin
    :param national_identity_number:
    :return: a list of formatted mobile numbers
    """
    return mobile_lookup_client.find_mobiles_by_NIN(national_identity_number, number_region)

@app.task
def find_NIN_by_mobile(mobile_number):
    """
    Searches nin with the registered mobile number
    :param mobile_number:
    :return: the nin with the registered mobile number
    """
    return mobile_lookup_client.find_NIN_by_mobile(mobile_number)