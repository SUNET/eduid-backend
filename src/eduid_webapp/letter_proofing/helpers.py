# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
from enum import unique

from eduid_common.api.messages import TranslatableMsg, error_message
from eduid_common.api.utils import get_short_hash
from eduid_userdb.proofing import LetterProofingState, NinProofingElement
from eduid_userdb.proofing.element import SentLetterElement

from eduid_webapp.letter_proofing import pdf
from eduid_webapp.letter_proofing.app import current_letterp_app as current_app

__author__ = 'lundberg'


@unique
class LetterMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # No letter proofing state found in the db
    no_state = 'letter.no_state_found'
    # a letter has already been sent
    already_sent = 'letter.already-sent'
    # the letter has been sent, but enough time has passed to send a new one
    letter_expired = 'letter.expired'
    # some unspecified problem sending the letter
    not_sent = 'letter.not-sent'
    # no postal address found
    address_not_found = 'letter.no-address-found'
    # errors in the format of the postal address
    bad_address = 'letter.bad-postal-address'
    # letter sent and state saved w/o errors
    letter_sent = 'letter.saved-unconfirmed'
    # wrong verification code received
    wrong_code = 'letter.wrong-code'
    # success verifying the code
    verify_success = 'letter.verification_success'


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
        max_wait = timedelta(hours=current_app.config.letter_wait_time_hours, minutes=minutes_until_midnight)

        time_since_sent = now - sent_dt
        if time_since_sent < max_wait:
            current_app.logger.info('User with eppn {!s} has to wait for letter to arrive.'.format(state.eppn))
            current_app.logger.info('Code expires: {!s}'.format(sent_dt + max_wait))
            # The user has to wait for the letter to arrive
            return {
                'letter_sent': sent_dt,
                'letter_expires': sent_dt + max_wait,
                'letter_expired': False,
                'message': LetterMsg.already_sent.value,
            }
        else:
            # If the letter haven't reached the user within the allotted time
            # remove the previous proofing object and restart the proofing flow
            current_app.logger.info('Letter expired for user with eppn {!s}.'.format(state.eppn))
            current_app.proofing_statedb.remove_document({'eduPersonPrincipalName': state.eppn})
            current_app.logger.info('Removed {!s}'.format(state))
            current_app.stats.count('letter_expired')
            return {
                'letter_sent': sent_dt,
                'letter_expires': sent_dt + max_wait,
                'letter_expired': True,
                'message': LetterMsg.letter_expired.value,
            }
    current_app.logger.info('Unfinished state for user with eppn {!s}'.format(state.eppn))
    return error_message(LetterMsg.not_sent)


def create_proofing_state(eppn: str, nin: str) -> LetterProofingState:
    _nin = NinProofingElement(
        number=nin,
        application='eduid-idproofing-letter',
        created_ts=True,
        verified=False,
        verification_code=get_short_hash(),
    )
    proofing_letter = SentLetterElement(data={})
    return LetterProofingState(id=None, modified_ts=None, eppn=eppn, nin=_nin, proofing_letter=proofing_letter)


def get_address(user, proofing_state):
    """
    :param user: User object
    :param proofing_state: Users proofing state

    :type user: eduid_userdb.proofing.ProofingUser
    :type proofing_state: eduid_userdb.proofing.LetterProofingState

    :return: Users offcial postal address
    :rtype: OrderedDict|None
    """
    current_app.logger.info('Getting address for user {}'.format(user))
    current_app.logger.debug('NIN: {!s}'.format(proofing_state.nin.number))
    # Lookup official address via Navet
    address = current_app.msg_relay.get_postal_address(proofing_state.nin.number)
    current_app.logger.debug('Official address: {!r}'.format(address))
    return address


def send_letter(user, proofing_state):
    """
    :param user: User object
    :param proofing_state: Users proofing state

    :type user: eduid_userdb.proofing.ProofingUser
    :type proofing_state: eduid_userdb.proofing.LetterProofingState

    :return: Transaction id
    :rtype: str|unicode
    """
    # Create the letter as a PDF-document and send it to our letter sender service
    pdf_letter = pdf.create_pdf(
        proofing_state.proofing_letter.address,
        proofing_state.nin.verification_code,
        proofing_state.nin.created_ts,
        user.mail_addresses.primary.email,
    )
    if current_app.config.ekopost_debug_pdf:
        # Write PDF to file instead of actually sending it if EKOPOST_DEBUG_PDF is set
        with open(current_app.config.ekopost_debug_pdf, 'wb') as fd:
            fd.write(pdf_letter.getvalue())
        return 'debug mode transaction id'
    campaign_id = current_app.ekopost.send(user.eppn, pdf_letter)
    return campaign_id
