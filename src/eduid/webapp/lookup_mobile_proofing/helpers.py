# -*- coding: utf-8 -*-

from datetime import datetime
from enum import unique
from typing import List, Optional

from eduid.common.rpc.lookup_mobile_relay import LookupMobileTaskFailed
from eduid.userdb import User
from eduid.userdb.logs import TeleAdressProofing, TeleAdressProofingRelation
from eduid.userdb.proofing.element import NinProofingElement
from eduid.userdb.proofing.state import NinProofingState
from eduid.userdb.proofing.user import ProofingUser
from eduid.userdb.util import utc_now
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.lookup_mobile_proofing.app import current_mobilep_app as current_app
from eduid.workers.lookup_mobile.utilities import format_NIN

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


def nin_to_age(nin: str, now: Optional[datetime] = None) -> int:
    """
    :param nin: National Identity Number, YYYYMMDDXXXX
    :return: Age in years
    """
    if now is None:
        now = utc_now()

    born = datetime.strptime(nin[: len('yyyymmdd')], '%Y%m%d')

    age = now.year - born.year - ((now.month, now.day) < (born.month, born.day))

    return age


def create_proofing_state(user: User, nin: str) -> NinProofingState:
    """
    :param user: Central userdb user
    :param nin: National Identity Number
    """
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    nin_element = NinProofingElement(number=nin, created_by='lookup_mobile_proofing', is_verified=False)
    return NinProofingState(id=None, modified_ts=None, eppn=proofing_user.eppn, nin=nin_element)


def match_mobile_to_user(
    user: User, self_asserted_nin: str, verified_mobile_numbers: List[str]
) -> Optional[TeleAdressProofing]:
    """
    :param user: Central userdb user
    :param self_asserted_nin: Self asserted national identity number
    :param verified_mobile_numbers: Verified mobile numbers

    :return: A proofing log entry on success
    """
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)

    # This code is to use the backdoor that allows selenium integration tests
    # to verify a NIN by sending a magic cookie
    if check_magic_cookie(current_app.conf):
        current_app.logger.info('Using the BACKDOOR to verify a NIN through the lookup mobile app')
        user_postal_address = {
            'Name': {'GivenName': 'Magic Cookie', 'GivenNameMarking': '20', 'Surname': 'Magic Cookie'},
            'OfficialAddress': {'Address2': 'Dummy address', 'City': 'LANDET', 'PostalCode': '12345'},
        }
        proofing_log_entry = TeleAdressProofing(
            eppn=proofing_user.eppn,
            created_by='lookup_mobile_proofing',
            reason='magic_cookie',
            nin=self_asserted_nin,
            mobile_number='dummy phone',
            user_postal_address=user_postal_address,
            proofing_version='2014v1',
        )
        current_app.stats.count('validate_nin_by_mobile_magic_cookie')
        return proofing_log_entry

    age = nin_to_age(self_asserted_nin)

    for mobile_number in verified_mobile_numbers:
        try:
            registered_to_nin = current_app.lookup_mobile_relay.find_nin_by_mobile(mobile_number)
            registered_to_nin = format_NIN(registered_to_nin)
            current_app.logger.debug(f'Mobile {mobile_number} registered to NIN: {registered_to_nin}')
        except LookupMobileTaskFailed:
            current_app.logger.error('Lookup mobile task failed for user')
            current_app.logger.debug(f'Mobile number: {mobile_number}')
            raise

        # Check if registered nin was the self asserted nin
        if registered_to_nin == self_asserted_nin:
            current_app.logger.info('Mobile number matched for user')
            current_app.logger.info('Looking up official address for user')
            user_postal_address = current_app.msg_relay.get_postal_address(self_asserted_nin)
            current_app.logger.info('Creating proofing log entry for user')
            proofing_log_entry = TeleAdressProofing(
                eppn=proofing_user.eppn,
                created_by='lookup_mobile_proofing',
                reason='matched',
                nin=self_asserted_nin,
                mobile_number=mobile_number,
                user_postal_address=user_postal_address,
                proofing_version='2014v1',
            )
            current_app.stats.count('validate_nin_by_mobile_exact_match')
            return proofing_log_entry
        # Check if registered nin is related to given nin if the user is under 18 years of age
        elif registered_to_nin and age < 18:
            relations = current_app.msg_relay.get_relations_to(self_asserted_nin, registered_to_nin)
            # FA - Fader
            # MO - Moder
            # VF - Vårdnadshavare för
            # F - Förälder
            valid_relations = ['FA', 'MO', 'VF', 'F']
            if any(r in relations for r in valid_relations):
                current_app.logger.info('Mobile number matched for user relation via navet.')
                current_app.logger.debug(f'Mobile {mobile_number} registered to NIN: {registered_to_nin}.')
                current_app.logger.debug(f'Person with NIN {registered_to_nin} have relation {relations} to user')
                current_app.logger.info('Looking up official address for user')
                user_postal_address = current_app.msg_relay.get_postal_address(self_asserted_nin)
                current_app.logger.info(f'Looking up official address for relation {relations}.')
                registered_postal_address = current_app.msg_relay.get_postal_address(registered_to_nin)
                current_app.logger.info('Creating proofing log entry for user')
                proofing_log_entry = TeleAdressProofingRelation(
                    eppn=proofing_user.eppn,
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
                return proofing_log_entry
        # No match
        else:
            current_app.logger.info(f'Mobile {mobile_number} number NOT matched to users NIN')
            current_app.logger.debug(f'Mobile registered to NIN: {registered_to_nin}')
            current_app.logger.debug(f'User NIN: {self_asserted_nin}')

    # None of the users verified mobile phone numbers matched the NIN
    current_app.stats.count('validate_nin_by_mobile_no_match')
    return None
