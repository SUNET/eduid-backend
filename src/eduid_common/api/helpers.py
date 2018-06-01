# -*- coding: utf-8 -*-
from __future__ import absolute_import

from flask import current_app

from eduid_userdb.proofing import ProofingUser
from eduid_userdb.nin import Nin

__author__ = 'lundberg'


def number_match_proofing(user, proofing_state, number):
    """
    :param user: Central userdb user
    :param proofing_state: Proofing state for user
    :param number: National identityt number

    :type user: eduid_userdb.user.User
    :type proofing_state: eduid_userdb.proofing.OidcProofingState
    :type number: six.string_types

    :return: True|False
    :rtype: bool
    """
    if proofing_state.nin.number == number:
        return True
    current_app.logger.error('Self asserted NIN does not match for user {}'.format(user))
    current_app.logger.debug('Self asserted NIN: {}. NIN from vetting provider {}'.format(
        proofing_state.nin.number, number))
    return False


def add_nin_to_user(user, proofing_state):
    """
    :param user: Central userdb user
    :param proofing_state: Proofing state for user

    :type user: eduid_userdb.user.User
    :type proofing_state: eduid_userdb.proofing.NinProofingState

    :return: None
    """
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    # Add nin to user if not already there
    if not proofing_user.nins.find(proofing_state.nin.number):
        current_app.logger.info('Adding NIN for user {}'.format(user))
        current_app.logger.debug('Self asserted NIN: {}'.format(proofing_state.nin.number))
        nin_element = Nin(number=proofing_state.nin.number, application=proofing_state.nin.created_by,
                          verified=proofing_state.nin.is_verified, created_ts=proofing_state.nin.created_ts,
                          primary=False)
        proofing_user.nins.add(nin_element)
        proofing_user.modified_ts = True
        # Save user to private db
        current_app.private_userdb.save(proofing_user, check_sync=False)
        # Ask am to sync user to central db
        current_app.logger.info('Request sync for user {!s}'.format(proofing_user))
        result = current_app.am_relay.request_user_sync(proofing_user)
        current_app.logger.info('Sync result for user {!s}: {!s}'.format(proofing_user, result))


def verify_nin_for_user(user, proofing_state, proofing_log_entry):
    """
    :param user: Central userdb user
    :param proofing_state: Proofing state for user
    :param proofing_log_entry: Proofing log entry element

    :type user: eduid_userdb.user.User
    :type proofing_state: eduid_userdb.proofing.NinProofingState
    :type proofing_log_entry: eduid_userdb.log.element.ProofingLogElement

    :return: None
    """
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    nin_element = proofing_user.nins.find(proofing_state.nin.number)
    if not nin_element:
        nin_element = Nin(number=proofing_state.nin.number, application=proofing_state.nin.created_by,
                          created_ts=proofing_state.nin.created_ts, verified=False, primary=False)
        proofing_user.nins.add(nin_element)

    # Check if the NIN is already verified
    if nin_element and nin_element.is_verified:
        current_app.logger.info('NIN is already verified for user {}'.format(proofing_user))
        current_app.logger.debug('NIN: {}'.format(proofing_state.nin.number))
        return

    # Update users nin element
    if proofing_user.nins.primary is None:
        # No primary NIN found, make the only verified NIN primary
        nin_element.is_primary = True
    nin_element.is_verified = True
    nin_element.verified_ts = True
    nin_element.verified_by = proofing_state.nin.created_by

    # If user was updated successfully continue with logging the proof and saving the user to central db
    # Send proofing data to the proofing log
    if current_app.proofing_log.save(proofing_log_entry):
        current_app.logger.info('Recorded verification for {} in the proofing log'.format(proofing_user))
        # User from central db is as up to date as it can be no need to check for modified time
        proofing_user.modified_ts = True
        # Save user to private db
        current_app.private_userdb.save(proofing_user, check_sync=False)

        # Ask am to sync user to central db
        current_app.logger.info('Request sync for user {!s}'.format(user))
        result = current_app.am_relay.request_user_sync(proofing_user)
        current_app.logger.info('Sync result for user {!s}: {!s}'.format(proofing_user, result))
