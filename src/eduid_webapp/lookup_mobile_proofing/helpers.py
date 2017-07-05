# -*- coding: utf-8 -*-

import time
from flask import current_app
from eduid_userdb.proofing.state import NinProofingState
from eduid_userdb.proofing.element import NinProofingElement
from eduid_userdb.proofing.user import ProofingUser
from eduid_userdb.logs import TeleAdressProofing, TeleAdressProofingRelation
from eduid_lookup_mobile.utilities import format_NIN
from eduid_webapp.lookup_mobile_proofing.lookup_mobile_relay import LookupMobileTaskFailed

__author__ = 'lundberg'


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


def create_proofing_state(user, nin):
    """
    :param user: Central userdb user
    :param nin: National Identity Number

    :type user: eduid_userdb.user.User
    :type nin: str

    :return: NinProofingState
    :rtype: eduid_userdb.proofing.NinProofingState
    """
    proofing_user = ProofingUser(data=user.to_dict())
    nin_element = NinProofingElement(number=nin, application='lookup_mobile_proofing', verified=False)
    proofing_state = NinProofingState({'eduPersonPrincipalName': proofing_user.eppn, 'nin': nin_element.to_dict()})
    return proofing_state


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
    proofing_user = ProofingUser(data=user.to_dict())
    age = nin_to_age(self_asserted_nin)

    for mobile_number in verified_mobile_numbers:
        try:
            registered_to_nin = current_app.lookup_mobile_relay.find_nin_by_mobile(mobile_number)
            registered_to_nin = format_NIN(registered_to_nin)
        except LookupMobileTaskFailed as e:
            current_app.logger.error('Lookup mobile task failed for user {!r}.'.format(proofing_user))
            current_app.logger.debug('Mobile number: {}'.format(mobile_number))
            raise e

        # Check if registered nin was the self asserted nin
        if registered_to_nin == self_asserted_nin:
            current_app.logger.info('Mobile number matched for user {!r}.'.format(proofing_user))
            current_app.logger.debug('Mobile {!s} registered to NIN: {!s}.'.format(mobile_number, registered_to_nin))

            current_app.logger.info('Creating proofing log entry for user {!r}.'.format(proofing_user))
            current_app.logger.info('Looking up official address for user {!r}.'.format(proofing_user))
            user_postal_address = current_app.msg_relay.get_postal_address(self_asserted_nin)
            proofing_log_entry = TeleAdressProofing(proofing_user, created_by='lookup_mobile_proofing',
                                                    reason='matched', nin=self_asserted_nin,
                                                    mobile_number=mobile_number,
                                                    user_postal_address=user_postal_address, proofing_version='2014v1')
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
                current_app.logger.debug('Person with NIN {} have relation {} to user: {}.'.format(
                    registered_to_nin, relations, user))
                current_app.logger.info('Creating proofing log entry for user {}.'.format(proofing_user))
                current_app.logger.info('Looking up official address for user {}.'.format(proofing_user))
                user_postal_address = current_app.msg_relay.get_postal_address(self_asserted_nin)
                current_app.logger.info('Looking up official address for relation {}.'.format(proofing_user))
                registered_postal_address = current_app.msg_relay.get_postal_address(registered_to_nin)
                proofing_log_entry = TeleAdressProofingRelation(proofing_user, created_by='lookup_mobile_proofing',
                                                                reason='match_by_navet', nin=self_asserted_nin,
                                                                mobile_number=mobile_number,
                                                                user_postal_address=user_postal_address,
                                                                mobile_number_registered_to=registered_to_nin,
                                                                registered_postal_address=registered_postal_address,
                                                                registered_relation=relations,
                                                                proofing_version='2014v1')
                current_app.stats.count('validate_nin_by_mobile_relative_match')
                return True, proofing_log_entry

    return False, None
