# -*- coding: utf-8 -*-

import time
from enum import unique

from eduid_common.api.helpers import check_magic_cookie
from eduid_common.api.messages import TranslatableMsg
from eduid_lookup_mobile.utilities import format_NIN
from eduid_userdb import User
from eduid_userdb.logs import TeleAdressProofing, TeleAdressProofingRelation
from eduid_userdb.proofing.element import NinProofingElement
from eduid_userdb.proofing.state import NinProofingState
from eduid_userdb.proofing.user import ProofingUser

from eduid_webapp.lookup_mobile_proofing.app import current_mobilep_app as current_app
from eduid_webapp.lookup_mobile_proofing.lookup_mobile_relay import LookupMobileTaskFailed

__author__ = 'lundberg'


@unique
class MobileMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # the user has no verified phones to use
    no_phone = 'no_phone'
    # problems looking up the phone
    lookup_error = 'error_lookup_mobile_task'
    # success verifying the NIN with the phone
    verify_success = 'letter.verification_success'
    # no match for the provided phone number
    no_match = 'nins.no-mobile-match'


def nin_to_age(nin):
    """
    :param nin: National Identity Number, YYYYMMDDXXXX
    :type nin: six.string_types
    :return: Age
    :rtype: int
    """
    current_year = int(time.strftime("%Y"))
    current_month = int(time.strftime("%m"))
    current_day = int(time.strftime("%d"))

    birth_year = int(nin[:4])
    birth_month = int(nin[4:6])
    birth_day = int(nin[6:8])

    age = current_year - birth_year

    if current_month < birth_month or (current_month == birth_month and current_day < birth_day):
        age -= 1

    return age


def create_proofing_state(user: User, nin: str) -> NinProofingState:
    """
    :param user: Central userdb user
    :param nin: National Identity Number
    """
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    nin_element = NinProofingElement.from_dict(dict(number=nin, created_by='lookup_mobile_proofing', verified=False))
    return NinProofingState(id=None, modified_ts=None, eppn=proofing_user.eppn, nin=nin_element)


def match_mobile_to_user(user, self_asserted_nin, verified_mobile_numbers):
    """
    :param user: Central userdb user
    :param self_asserted_nin: Self asserted national identity number
    :param verified_mobile_numbers: Verified mobile numbers

    :type user: eduid_userdb.user.User
    :type self_asserted_nin: six.string_types
    :type verified_mobile_numbers: list

    :return: True|False, proofing_log_entry|None
    :rtype: tuple
    """
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)

    # This code is to use the backdoor that allows selenium integration tests
    # to verify a NIN by sending a magic cookie
    if check_magic_cookie(current_app.config):
        current_app.logger.info('Using the BACKDOOR to verify a NIN through the lookup mobile app')
        user_postal_address = {
            'Name': {'GivenName': 'Magic Cookie', 'GivenNameMarking': '20', 'Surname': 'Magic Cookie'},
            'OfficialAddress': {'Address2': 'Dummy address', 'City': 'LANDET', 'PostalCode': '12345'},
        }
        proofing_log_entry = TeleAdressProofing(
            proofing_user,
            created_by='lookup_mobile_proofing',
            reason='magic_cookie',
            nin=self_asserted_nin,
            mobile_number='dummy phone',
            user_postal_address=user_postal_address,
            proofing_version='2014v1',
        )
        current_app.stats.count('validate_nin_by_mobile_magic_cookie')
        return True, proofing_log_entry

    age = nin_to_age(self_asserted_nin)

    for mobile_number in verified_mobile_numbers:
        try:
            registered_to_nin = current_app.lookup_mobile_relay.find_nin_by_mobile(mobile_number)
            registered_to_nin = format_NIN(registered_to_nin)
        except LookupMobileTaskFailed as e:
            current_app.logger.error('Lookup mobile task failed for user {}.'.format(proofing_user))
            current_app.logger.debug('Mobile number: {}'.format(mobile_number))
            raise e

        # Check if registered nin was the self asserted nin
        if registered_to_nin == self_asserted_nin:
            current_app.logger.info('Mobile number matched for user {}.'.format(proofing_user))
            current_app.logger.debug('Mobile {!s} registered to NIN: {!s}.'.format(mobile_number, registered_to_nin))

            current_app.logger.info('Creating proofing log entry for user {}.'.format(proofing_user))
            current_app.logger.info('Looking up official address for user {}.'.format(proofing_user))
            user_postal_address = current_app.msg_relay.get_postal_address(self_asserted_nin)
            proofing_log_entry = TeleAdressProofing(
                proofing_user,
                created_by='lookup_mobile_proofing',
                reason='matched',
                nin=self_asserted_nin,
                mobile_number=mobile_number,
                user_postal_address=user_postal_address,
                proofing_version='2014v1',
            )
            current_app.stats.count('validate_nin_by_mobile_exact_match')
            return True, proofing_log_entry
        # Check if registered nin is related to given nin if the user is under 18 years of age
        elif registered_to_nin and age < 18:
            relations = current_app.msg_relay.get_relations_to(self_asserted_nin, registered_to_nin)
            # FA - Fader
            # MO - Moder
            # VF - Vårdnadshavare för
            # F - Förälder
            valid_relations = ['FA', 'MO', 'VF', 'F']
            if any(r in relations for r in valid_relations):
                current_app.logger.info('Mobile number matched for user {} via navet.'.format(user))
                current_app.logger.debug('Mobile {} registered to NIN: {}.'.format(mobile_number, registered_to_nin))
                current_app.logger.debug(
                    'Person with NIN {} have relation {} to user: {}.'.format(registered_to_nin, relations, user)
                )
                current_app.logger.info('Creating proofing log entry for user {}.'.format(proofing_user))
                current_app.logger.info('Looking up official address for user {}.'.format(proofing_user))
                user_postal_address = current_app.msg_relay.get_postal_address(self_asserted_nin)
                current_app.logger.info('Looking up official address for relation {}.'.format(proofing_user))
                registered_postal_address = current_app.msg_relay.get_postal_address(registered_to_nin)
                proofing_log_entry = TeleAdressProofingRelation(
                    proofing_user,
                    created_by='lookup_mobile_proofing',
                    reason='match_by_navet',
                    nin=self_asserted_nin,
                    mobile_number=mobile_number,
                    user_postal_address=user_postal_address,
                    mobile_number_registered_to=registered_to_nin,
                    registered_postal_address=registered_postal_address,
                    registered_relation=relations,
                    proofing_version='2014v1',
                )
                current_app.stats.count('validate_nin_by_mobile_relative_match')
                return True, proofing_log_entry

    current_app.logger.info('Mobile number NOT matched for user {}.'.format(proofing_user))
    return False, None
