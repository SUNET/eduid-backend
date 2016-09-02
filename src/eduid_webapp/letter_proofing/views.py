# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Blueprint, current_app
from flask_apispec import use_kwargs, marshal_with
import json

from eduid_common.api.decorators import require_user
from eduid_common.api.schemas.proofing_data import LetterProofingDataSchema  # XXX: Until we no longer wants to dump proofing to log
from eduid_common.api.exceptions import ApiException
from eduid_userdb.proofing import ProofingUser
from eduid_userdb.nin import Nin
from eduid_webapp.letter_proofing import pdf
from eduid_webapp.letter_proofing import schemas
from eduid_webapp.letter_proofing.proofing import create_proofing_state, check_state

__author__ = 'lundberg'

idproofing_letter_views = Blueprint('idproofing_letter', __name__, url_prefix='', template_folder='templates')


@idproofing_letter_views.route('/get-state', methods=['GET'])
@marshal_with(schemas.GetStateResponseSchema)
@require_user
def get_state(user):
    current_app.logger.info('Getting proofing state for user {!r}'.format(user))
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn, raise_on_missing=False)
    if not proofing_state:
        # No warning as proofing state can be None
        proofing_state = current_app.proofing_statedb.get_state_by_user_id(user.user_id, user.eppn,
                                                                           raise_on_missing=False)
    if proofing_state:
        current_app.logger.info('Found proofing state for user {!r}'.format(user))
        # If a proofing state is found continue the flow
        return check_state(proofing_state)
    response = {
        'expected_fields': schemas.SendLetterRequestSchema().fields.keys()
    }
    return response


@idproofing_letter_views.route('/send-letter', methods=['POST'])
@use_kwargs(schemas.SendLetterRequestSchema)
@marshal_with(schemas.GetStateResponseSchema)
@require_user
def send_letter(user, **kwargs):
    nin = kwargs.get('nin')
    current_app.logger.info('Send letter for user {!r} initiated'.format(user))

    # Look for existing proofing state
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn, raise_on_missing=False)
    if not proofing_state:
        # No warning as proofing state can be None
        proofing_state = current_app.proofing_statedb.get_state_by_user_id(user.user_id, user.eppn,
                                                                           raise_on_missing=False)

    # No existing proofing state was found, create a new one
    if not proofing_state:
        # Create a LetterNinProofingUser in proofingdb
        proofing_state = create_proofing_state(user.eppn, nin)
        current_app.logger.info('Created proofing state for user {!r}'.format(user))

    current_app.logger.info('Getting address for user {!r}'.format(user))
    current_app.logger.debug('NIN: {!s}'.format(nin))
    # Lookup official address via Navet
    address = current_app.msg_relay.get_postal_address(nin)
    if not address:
        current_app.logger.error('No address found for user {!r}'.format(user))
        raise ApiException('No address found', status_code=400)
    current_app.logger.debug('Official address: {!r}'.format(address))

    if proofing_state.proofing_letter.is_sent:
        current_app.logger.info('User {!r} has already sent a letter'.format(user))
        return check_state(proofing_state)

    # Check that user is not trying to register another NIN
    if not proofing_state.nin.number == nin:
        current_app.logger.error('NIN mismatch for user {!r}'.format(user))
        current_app.logger.error('Old NIN: {!s}'.format(proofing_state.nin.number))
        current_app.logger.error('New NIN: {!s}'.format(nin))
        raise ApiException('NIN mismatch', status_code=400)

    # Set or update official address
    proofing_state.proofing_letter.address = address
    current_app.proofing_statedb.save(proofing_state)

    # User accepted a letter to their official address and data saved in db checks out
    # and therefore we can now create the letter as a PDF-document and send it.
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
            raise api_exception

    # Save the users proofing state
    proofing_state.proofing_letter.transaction_id = campaign_id
    proofing_state.proofing_letter.is_sent = True
    proofing_state.proofing_letter.sent_ts = True
    current_app.proofing_statedb.save(proofing_state)
    return check_state(proofing_state)


@idproofing_letter_views.route('/verify-code', methods=['POST'])
@use_kwargs(schemas.VerifyCodeRequestSchema)
@marshal_with(schemas.VerifyCodeResponseSchema)
@require_user
def verify_code(user, **kwargs):
    user = ProofingUser(data=user.to_dict())
    current_app.logger.info('Verifying code for user {!r}'.format(user))
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn, raise_on_missing=False)
    if not proofing_state:
        current_app.logger.warning('Proofing state looked up by user_id')
        proofing_state = current_app.proofing_statedb.get_state_by_user_id(user.user_id, user.eppn,
                                                                           raise_on_missing=True)
    if not kwargs.get('verification_code') == proofing_state.nin.verification_code:
        current_app.logger.error('Verification code for user {!r} does not match'.format(user))
        # TODO: Throttling to discourage an adversary to try brute force
        return {'success': False, 'message': 'Verification code does not match'}

    # Update proofing state to use to create nin element
    proofing_state.nin.is_verified = True
    proofing_state.nin.verified_by = 'eduid-idproofing-letter'
    proofing_state.nin.verified_ts = True
    nin = Nin(data=proofing_state.nin.to_dict())
    # Save user to private db
    user.nins.add(nin)
    # User from central db is as up to date as it can be no need to check for modified time
    current_app.proofing_userdb.save(user, check_sync=False)
    try:
        current_app.logger.info('Request sync for user {!s}'.format(user))
        result = current_app.am_relay.request_sync(user)
        current_app.logger.info('Sync result for user {!s}: {!s}'.format(user, result))
    except Exception as e:
        current_app.logger.error('Sync request failed for user {!s}'.format(user))
        current_app.logger.error('Exception: {!s}'.format(e))
        raise ApiException(e, payload={'success': False})

    # XXX: Send proofing data to some kind of proofing log

    # XXX: Do not add letter_proofing_data after we update to new db models in central user db
    letter_proofing_data = proofing_state.nin.to_dict()
    letter_proofing_data['official_address'] = proofing_state.proofing_letter.address
    letter_proofing_data['transaction_id'] = proofing_state.proofing_letter.transaction_id
    user.add_letter_proofing_data(letter_proofing_data)
    # XXX: Remove dumping data to log
    current_app.logger.info('Logging data for user: {!r}'.format(user))
    current_app.logger.info(json.dumps(LetterProofingDataSchema().dump(letter_proofing_data)))
    current_app.logger.info('End data')
    current_app.logger.info('Verified code for user {!r}'.format(user))

    # Remove proofing user
    current_app.proofing_statedb.remove_document({'eduPersonPrincipalName': proofing_state.eppn})
    return {'success': True}

