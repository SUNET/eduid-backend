# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Blueprint, current_app

from eduid_common.api.decorators import require_user, can_verify_identity, MarshalWith, UnmarshalWith
from eduid_userdb.proofing import ProofingUser
from eduid_userdb.logs import LetterProofing
from eduid_userdb.nin import Nin
from eduid_webapp.letter_proofing import pdf
from eduid_webapp.letter_proofing import schemas
from eduid_webapp.letter_proofing.ekopost import EkopostException
from eduid_webapp.letter_proofing.helpers import create_proofing_state, check_state, get_address, send_letter

__author__ = 'lundberg'

letter_proofing_views = Blueprint('letter_proofing', __name__, url_prefix='', template_folder='templates')


@letter_proofing_views.route('/proofing', methods=['GET'])
@MarshalWith(schemas.LetterProofingResponseSchema)
@require_user
def get_state(user):
    current_app.logger.info('Getting proofing state for user {!r}'.format(user))
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn, raise_on_missing=False)

    if proofing_state:
        current_app.logger.info('Found proofing state for user {!r}'.format(user))
        return check_state(proofing_state)
    return {}


@letter_proofing_views.route('/proofing', methods=['POST'])
@UnmarshalWith(schemas.LetterProofingRequestSchema)
@MarshalWith(schemas.LetterProofingResponseSchema)
@can_verify_identity
@require_user
def proofing(user, nin):
    current_app.logger.info('Send letter for user {!r} initiated'.format(user))
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn, raise_on_missing=False)

    # No existing proofing state was found, create a new one
    if not proofing_state:
        # Create a LetterNinProofingUser in proofingdb
        proofing_state = create_proofing_state(user.eppn, nin)
        current_app.logger.info('Created proofing state for user {!r}'.format(user))

    if proofing_state.proofing_letter.is_sent:
        current_app.logger.info('User {!r} has already sent a letter'.format(user))
        return check_state(proofing_state)

    address = get_address(user, proofing_state)
    if not address:
        current_app.logger.error('No address found for user {!r}'.format(user))
        return {'_status': 'error', 'message': 'No address found'}

    # Set and save official address
    proofing_state.proofing_letter.address = address
    current_app.proofing_statedb.save(proofing_state)

    try:
        campaign_id = send_letter(user, proofing_state)
    except pdf.AddressFormatException as e:
        current_app.logger.error('{!r}'.format(e.message))
        return {'_status': 'error', 'message': 'Bad postal address'}
    except EkopostException as e:
        current_app.logger.error('{!r}'.format(e.message))
        return {'_status': 'error', 'message': 'Temporary technical problem'}

    # Save the users proofing state
    proofing_state.proofing_letter.transaction_id = campaign_id
    proofing_state.proofing_letter.is_sent = True
    proofing_state.proofing_letter.sent_ts = True
    current_app.proofing_statedb.save(proofing_state)
    payload = check_state(proofing_state)
    return payload


@letter_proofing_views.route('/verify-code', methods=['POST'])
@UnmarshalWith(schemas.VerifyCodeRequestSchema)
@MarshalWith(schemas.VerifyCodeResponseSchema)
@require_user
def verify_code(user, verification_code):
    user = ProofingUser(data=user.to_dict())
    current_app.logger.info('Verifying code for user {!r}'.format(user))
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn, raise_on_missing=False)

    if not proofing_state:
        return {'_status': 'error', 'message': 'No proofing state found'}

    # Check if provided code matches the one in the letter
    if not verification_code == proofing_state.nin.verification_code:
        current_app.logger.error('Verification code for user {!r} does not match'.format(user))
        # TODO: Throttling to discourage an adversary to try brute force
        return {'_status': 'error', 'message': 'Wrong code'}

    # Update proofing state to use to create nin element
    proofing_state.nin.is_verified = True
    proofing_state.nin.verified_by = 'eduid-letter-proofing'
    proofing_state.nin.verified_ts = True
    nin = Nin(number=proofing_state.nin.number, application=proofing_state.nin.created_by,
              verified=proofing_state.nin.is_verified, created_ts=proofing_state.nin.created_ts,
              primary=False)
    nin.verified_by = proofing_state.nin.verified_by
    # Save user to private db
    if user.nins.primary is None:  # No primary NIN found, make the only verified NIN primary
        nin.is_primary = True
    user.nins.add(nin)

    official_address = get_address(user, proofing_state)
    letter_proof = LetterProofing(user, created_by='eduid_letter_proofing', nin=nin.number,
                                  letter_sent_to=proofing_state.proofing_letter.address,
                                  transaction_id=proofing_state.proofing_letter.transaction_id,
                                  user_postal_address=official_address, proofing_version='2016v1')

    if current_app.proofing_log.save(letter_proof):
        current_app.logger.info('Recorded verification for {} in the proofing log'.format(user))
        # User from central db is as up to date as it can be no need to check for modified time
        user.modified_ts = True
        current_app.proofing_userdb.save(user, check_sync=False)

        # Ask am to sync user to central db
        try:
            current_app.logger.info('Request sync for user {!s}'.format(user))
            result = current_app.am_relay.request_user_sync(user)
            current_app.logger.info('Sync result for user {!s}: {!s}'.format(user, result))
        except Exception as e:
            current_app.logger.error('Sync request failed for user {!s}'.format(user))
            current_app.logger.error('Exception: {!s}'.format(e))
            return {'_status': 'error', 'message': 'Sync request failed for user'}

        current_app.logger.info('Verified code for user {!r}'.format(user))
        # Remove proofing state
        current_app.proofing_statedb.remove_document({'eduPersonPrincipalName': proofing_state.eppn})
        return {'success': True}
    return {'_status': 'error', 'message': 'Temporary technical problems. Please try again later.'}
