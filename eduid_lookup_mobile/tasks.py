from __future__ import absolute_import
from eduid_lookup_mobile.celery import app
from eduid_lookup_mobile.client.mobile_lookup_client import MobileLookupClient

@app.task
def verify_identity(national_identity_number, mobile_number_list):
    """
    Verify that one of the mobile numbers are registered to the given nin or parent
    :param national_identity_number:
    :param mobile_number_list:
    :return: {'success': boolean, 'status': string, 'mobile': string}
              success is true or false depending on if the validation was successful or not.
              status holds information about the verification. no_phone, no_match, match, match_by_navet, bad_input
              mobile holds the mobile number that where used to do the validation
    """
    lookup_client = MobileLookupClient()
    return lookup_client.verify_identity(national_identity_number, mobile_number_list)

@app.task
def find_mobiles_by_NIN(national_identity_number, number_region=None):
    """
    Searches mobile numbers registered to the given nin
    :param national_identity_number:
    :return: a list of formatted mobile numbers
    """
    lookup_client = MobileLookupClient()
    return lookup_client.find_mobiles_by_NIN(national_identity_number, number_region)

@app.task
def find_NIN_by_mobile(mobile_number):
    """
    Searches nin with the registered mobile number
    :param mobile_number:
    :return: the nin with the registered mobile number
    """
    lookup_client = MobileLookupClient()
    return lookup_client.find_NIN_by_mobile(mobile_number)
