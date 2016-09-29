# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Blueprint, current_app, request

import json  # XXX: Until we no longer wants to dump proofing to log

from eduid_common.api.decorators import require_user, MarshalWith, UnmarshalWith
from eduid_common.api.exceptions import ApiException
from eduid_userdb.proofing import ProofingUser
from eduid_userdb.nin import Nin
from eduid_webapp.letter_proofing import pdf
from eduid_webapp.letter_proofing import schemas
from eduid_webapp.letter_proofing.proofing import create_proofing_state, check_state

__author__ = 'lundberg'

letter_proofing_views = Blueprint('letter_proofing', __name__, url_prefix='', template_folder='templates')


@letter_proofing_views.route('/proofing', methods=['GET', 'POST'])
@UnmarshalWith(schemas.LetterProofingRequestSchema)
@MarshalWith(schemas.LetterProofingResponseSchema)
@require_user
def proofing(user, nin):
    current_app.logger.info('Getting proofing state for user {!r}'.format(user))
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn, raise_on_missing=False)

    if request.method == 'GET':
        if proofing_state:
            current_app.logger.info('Found proofing state for user {!r}'.format(user))
            # If a proofing state is found continue the flow
            payload = check_state(proofing_state)
            return {'type': 'GET_LETTER_PROOFING', 'payload': payload}
        return {'type': 'GET_LETTER_PROOFING'}

    if request.method == 'POST' and nin:
        current_app.logger.info('Send letter for user {!r} initiated'.format(user))

        # For now a user can just have one verified NIN
        # TODO: Check if a user has a valid letter proofing
        if len(user.nins.to_list()) > 0:
            raise ApiException('POST_LETTER_PROOFING_FAIL', 'User is already verified', status_code=200)

        # No existing proofing state was found, create a new one
        if not proofing_state:
            # Create a LetterNinProofingUser in proofingdb
            proofing_state = create_proofing_state(user.eppn, nin)
            current_app.logger.info('Created proofing state for user {!r}'.format(user))

        if proofing_state.proofing_letter.is_sent:
            current_app.logger.info('User {!r} has already sent a letter'.format(user))
            raise ApiException('POST_LETTER_PROOFING_FAIL', 'Letter already sent', status_code=200)

        current_app.logger.info('Getting address for user {!r}'.format(user))
        current_app.logger.debug('NIN: {!s}'.format(nin))
        # Lookup official address via Navet
        address = current_app.msg_relay.get_postal_address(nin)
        if not address:
            current_app.logger.error('No address found for user {!r}'.format(user))
            raise ApiException('POST_LETTER_PROOFING_FAIL', 'No address found', status_code=200)
        current_app.logger.debug('Official address: {!r}'.format(address))

        # Set and save official address
        proofing_state.proofing_letter.address = address
        current_app.proofing_statedb.save(proofing_state)

        # Create the letter as a PDF-document and send it to our letter sender service
        if current_app.config.get("EKOPOST_DEBUG_PDF", None):
            pdf.create_pdf(proofing_state.proofing_letter.address,
                           proofing_state.nin.verification_code,
                           proofing_state.nin.created_ts,
                           user.mail_addresses.primary.email)
            campaign_id = 'debug mode transaction id'
        else:
            pdf_letter = pdf.create_pdf(proofing_state.proofing_letter.address,
                                        proofing_state.nin.verification_code,
                                        proofing_state.nin.created_ts,
                                        user.mail_addresses.primary.email)
            try:
                campaign_id = current_app.ekopost.send(user.eppn, pdf_letter)
            except ApiException as api_exception:
                current_app.logger.error('ApiException {!r}'.format(api_exception.message))
                api_exception.flux_type = 'POST_LETTER_PROOFING_FAIL'
                raise api_exception

        # Save the users proofing state
        proofing_state.proofing_letter.transaction_id = campaign_id
        proofing_state.proofing_letter.is_sent = True
        proofing_state.proofing_letter.sent_ts = True
        current_app.proofing_statedb.save(proofing_state)
        payload = check_state(proofing_state)
        return {'type': 'POST_LETTER_PROOFING_SUCCESS', 'payload': payload}


@letter_proofing_views.route('/verify-code', methods=['POST'])
@UnmarshalWith(schemas.VerifyCodeRequestSchema)
@MarshalWith(schemas.VerifyCodeResponseSchema)
@require_user
def verify_code(user, verification_code):
    user = ProofingUser(data=user.to_dict())
    current_app.logger.info('Verifying code for user {!r}'.format(user))
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn, raise_on_missing=False)

    if not proofing_state:
        raise ApiException('POST_LETTER_VERIFY_CODE_FAIL', message='No proofing state found', status_code=400)

    # Check if provided code matches the one in the letter
    if not verification_code == proofing_state.nin.verification_code:
        current_app.logger.error('Verification code for user {!r} does not match'.format(user))
        # TODO: Throttling to discourage an adversary to try brute force
        raise ApiException('POST_LETTER_VERIFY_CODE_FAIL', message='Wrong code', payload={'success': False},
                           status_code=200)

    # Update proofing state to use to create nin element
    proofing_state.nin.is_verified = True
    proofing_state.nin.verified_by = 'eduid-idproofing-letter'
    proofing_state.nin.verified_ts = True
    nin = Nin(data=proofing_state.nin.to_dict())

    # Save user to private db
    if user.nins.primary is None:  # No primary NIN found, make the only verified NIN primary
        nin.is_primary = True
    user.nins.add(nin)

    # XXX: Do not add letter_proofing_data after we update to new db models in central user db
    letter_proofing_data = proofing_state.nin.to_dict()
    letter_proofing_data['official_address'] = proofing_state.proofing_letter.address
    letter_proofing_data['transaction_id'] = proofing_state.proofing_letter.transaction_id
    user.add_letter_proofing_data(letter_proofing_data)

    # User from central db is as up to date as it can be no need to check for modified time
    user.modified_ts = True
    current_app.proofing_userdb.save(user, check_sync=False)

    # TODO: Need to decide where to "steal" NIN if multiple users have the NIN verified
    # Ask am to sync user to central db
    try:
        # XXX: Send proofing data to some kind of proofing log
        current_app.logger.info('Request sync for user {!s}'.format(user))
        result = current_app.am_relay.request_user_sync(user)
        current_app.logger.info('Sync result for user {!s}: {!s}'.format(user, result))
    except Exception as e:
        current_app.logger.error('Sync request failed for user {!s}'.format(user))
        current_app.logger.error('Exception: {!s}'.format(e))
        # XXX: Probably not str(e) as message?
        raise ApiException('POST_LETTER_VERIFY_CODE_FAIL', message=str(e), payload={'success': False})

    # XXX: Remove dumping data to log
    current_app.logger.info('Logging data for user: {!r}'.format(user))
    current_app.logger.info(json.dumps(schemas.LetterProofingDataSchema().dump(letter_proofing_data)))
    current_app.logger.info('End data')

    current_app.logger.info('Verified code for user {!r}'.format(user))
    # Remove proofing state
    current_app.proofing_statedb.remove_document({'eduPersonPrincipalName': proofing_state.eppn})
    return {
        'type': 'POST_LETTER_VERIFY_CODE_SUCCESS',
        'payload': {'success': True}
    }
