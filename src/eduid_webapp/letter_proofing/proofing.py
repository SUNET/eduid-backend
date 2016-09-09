# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import current_app
from datetime import datetime, timedelta

from eduid_userdb.proofing import LetterProofingState
from eduid_common.api.utils import get_short_hash

__author__ = 'lundberg'


def check_state(state):
    """
    :param state:  Users proofing state
    :type state:  LetterProofingState
    :return: payload
    :rtype: dict
    """
    current_app.logger.info('Checking state for user with eppn {!s}'.format(state.eppn))
    if state.proofing_letter.is_sent:
        current_app.logger.info('Letter is sent for user with eppn {!s}'.format(state.eppn))
        # Check how long ago the letter was sent
        sent_dt = state.proofing_letter.sent_ts
        minutes_until_midnight = (24 - sent_dt.hour) * 60  # Give the user until midnight the day the code expires
        now = datetime.now(sent_dt.tzinfo)  # Use tz_info from timezone aware mongodb datetime
        max_wait = timedelta(hours=current_app.config['LETTER_WAIT_TIME_HOURS'], minutes=minutes_until_midnight)

        time_since_sent = now - sent_dt
        if time_since_sent < max_wait:
            current_app.logger.info('User with eppn {!s} has to wait for letter to arrive.'.format(state.eppn))
            current_app.logger.info('Code expires: {!s}'.format(sent_dt + max_wait))
            # The user has to wait for the letter to arrive
            return {
                'letter_sent': sent_dt,
                'letter_expires': sent_dt + max_wait,
            }
        else:
            # If the letter haven't reached the user within the allotted time
            # remove the previous proofing object and restart the proofing flow
            current_app.logger.info('Letter expired for user with eppn {!s}.'.format(state.eppn))
            current_app.proofing_statedb.remove_document({'eduPersonPrincipalName': state.eppn})
            current_app.logger.info('Removed {!s}'.format(state))
            return {
                'letter_expired': True,
            }
    current_app.logger.info('Unfinished state for user with eppn {!s}'.format(state.eppn))
    return {}


def create_proofing_state(eppn, nin):
    proofing_state = LetterProofingState({
        'eduPersonPrincipalName': eppn,
        'nin': {
            'number': nin,
            'created_by': 'eduid-idproofing-letter',
            'created_ts': True,
            'verified': False,
            'verification_code': get_short_hash()
        }
    })
    return proofing_state
