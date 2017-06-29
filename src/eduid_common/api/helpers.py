# -*- coding: utf-8 -*-
from __future__ import absolute_import

from flask import current_app

from eduid_userdb.proofing import ProofingUser
from eduid_userdb.nin import Nin

__author__ = 'lundberg'


def add_nin_to_user(user, proofing_state):
    """
    :param user: Central userdb user
    :param proofing_state: Proofing state for user

    :type user: eduid_userdb.user.User
    :type proofing_state: eduid_userdb.proofing.NinProofingState

    :return: None
    """
    proofing_user = ProofingUser(data=user.to_dict())
    # Add nin to user if not already there
    if not proofing_user.nins.find(proofing_state.nin.number):
        nin_element = Nin(number=proofing_state.nin.number, application=proofing_state.nin.created_by,
                          verified=proofing_state.nin.is_verified, created_ts=proofing_state.nin.created_ts,
                          primary=False)
        proofing_user.nins.add(nin_element)
        proofing_user.modified_ts = True
        # Save user to private db
        current_app.proofing_userdb.save(proofing_user, check_sync=False)
        # Ask am to sync user to central db
        try:
            current_app.logger.info('Request sync for user {!s}'.format(proofing_user))
            result = current_app.am_relay.request_user_sync(proofing_user)
            current_app.logger.info('Sync result for user {!s}: {!s}'.format(proofing_user, result))
        except Exception as e:
            current_app.logger.error('Sync request failed for user {!s}'.format(proofing_user))
            current_app.logger.error('Exception: {!s}'.format(e))


def verify_nin_for_user(user, proofing_state, number, proofing_log_entry):
    """
    :param user: Central userdb user
    :param proofing_state: Proofing state for user
    :param number: National Identitly Number
    :param proofing_log_entry: Proofing log entry element

    :type user: eduid_userdb.user.User
    :type proofing_state: eduid_userdb.proofing.NinProofingState
    :type number: string_types
    :type proofing_log_entry: eduid_userdb.log.element.ProofingLogElement

    :return: None
    """
    proofing_user = ProofingUser(data=user.to_dict())
    # Check if the self professed NIN is the same as the NIN returned by the vetting provider
    if proofing_state.nin.number != number:
        current_app.logger.error('NIN does not match for user {}'.format(proofing_user))
        current_app.logger.debug('Self professed NIN: {}. NIN from vetting provider {}'.format(
            proofing_state.nin.number, number))
        return
    # Check if the NIN is already verified
    elif any(nin for nin in proofing_user.nins.verified.to_list() if nin.number == number):
        current_app.logger.info('NIN is already verified for user {}'.format(proofing_user))
        current_app.logger.debug('NIN: {}'.format(number))
        return
    proofing_state.nin.is_verified = True
    proofing_state.nin.verified_by = 'eduid-oidc-proofing'
    proofing_state.nin.verified_ts = True
    nin = proofing_user.nins.find(proofing_state.nin.number)
    if not nin:
        nin = Nin(number=proofing_state.nin.number, application=proofing_state.nin.created_by,
                  verified=proofing_state.nin.is_verified, created_ts=proofing_state.nin.created_ts,
                  primary=False)
    nin.verified_by = proofing_state.nin.verified_by
    nin.verified_by = nin.created_by
    # Check if the user has more than one verified nin
    if proofing_user.nins.primary is None:
        # No primary NIN found, make the only verified NIN primary
        nin.is_primary = True
        proofing_user.nins.add(nin)

    # If user was updated successfully continue with logging the proof and saving the user to central db
    # Send proofing data to the proofing log

    if current_app.proofing_log.save(proofing_log_entry):
        current_app.logger.info('Recorded verification for {} in the proofing log'.format(proofing_user))
        # User from central db is as up to date as it can be no need to check for modified time
        proofing_user.modified_ts = True
        # Save user to private db
        current_app.proofing_userdb.save(proofing_user, check_sync=False)

        # Ask am to sync user to central db
        try:
            current_app.logger.info('Request sync for user {!s}'.format(user))
            result = current_app.am_relay.request_user_sync(proofing_user)
            current_app.logger.info('Sync result for user {!s}: {!s}'.format(proofing_user, result))
        except Exception as e:
            current_app.logger.error('Sync request failed for user {!s}'.format(proofing_user))
            current_app.logger.error('Exception: {!s}'.format(e))
            # TODO: Need to able to retry
