# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import current_app
from datetime import datetime, timedelta

from eduid_userdb.proofing import LetterProofingState
from eduid_common.api.utils import get_short_hash
from eduid_webapp.letter_proofing.schemas import SendLetterRequestSchema, VerifyCodeRequestSchema

__author__ = 'lundberg'


def check_state(state):
    """
    :param state:  Users proofing state
    :type state:  LetterProofingState
    :return: response
    :rtype: dict
    """
    ret = dict()
    current_app.logger.info('Checking state for user with eppn {!s}'.format(state.eppn))
    if not state.proofing_letter.is_sent:
        current_app.logger.info('Letter is not sent for user with eppn {!s}'.format(state.eppn))
        # User needs to accept sending a letter
        ret.update({
            'expected_fields': SendLetterRequestSchema().fields.keys()  # Do we want expected_fields?
        })
    elif state.proofing_letter.is_sent:
        current_app.logger.info('Letter is sent for user with eppn {!s}'.format(state.eppn))
        # Check how long ago the letter was sent
        sent_dt = state.proofing_letter.sent_ts
        now = datetime.now(sent_dt.tzinfo)  # Use tz_info from timezone aware mongodb datetime
        max_wait = timedelta(hours=current_app.config['LETTER_WAIT_TIME_HOURS'])

        time_since_sent = now - sent_dt
        if time_since_sent < max_wait:
            current_app.logger.info('User with eppn {!s} has to wait for letter to arrive.'.format(state.eppn))
            current_app.logger.info('Code expires: {!s}'.format(sent_dt + max_wait))
            # The user has to wait for the letter to arrive
            ret.update({
                'letter_sent': sent_dt,
                'letter_expires': sent_dt + max_wait,
                'expected_fields': VerifyCodeRequestSchema().fields.keys(),  # Do we want expected_fields?
            })
        else:
            # If the letter haven't reached the user within the allotted time
            # remove the previous proofing object and restart the proofing flow
            current_app.logger.info('Letter expired for user with eppn {!s}.'.format(state.eppn))
            current_app.proofing_statedb.remove_document({'eduPersonPrincipalName': state.eppn})
            current_app.logger.info('Removed {!s}'.format(state))
            ret.update({
                'letter_expired': True,
                'expected_fields': SendLetterRequestSchema().fields.keys(),  # Do we want expected_fields?
            })
    return ret


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
