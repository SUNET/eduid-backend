# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Blueprint, abort

from eduid_common.api.decorators import MarshalWith, UnmarshalWith, can_verify_identity, require_user
from eduid_common.api.exceptions import AmTaskFailed, MsgTaskFailed
from eduid_common.api.helpers import add_nin_to_user, check_magic_cookie, verify_nin_for_user
from eduid_common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid_userdb import User
from eduid_userdb.logs import LetterProofing
from eduid_userdb.proofing import ProofingUser

from eduid_webapp.letter_proofing import pdf, schemas
from eduid_webapp.letter_proofing.app import current_letterp_app as current_app
from eduid_webapp.letter_proofing.ekopost import EkopostException
from eduid_webapp.letter_proofing.helpers import LetterMsg, check_state, create_proofing_state, get_address, send_letter

__author__ = 'lundberg'

letter_proofing_views = Blueprint('letter_proofing', __name__, url_prefix='', template_folder='templates')


@letter_proofing_views.route('/proofing', methods=['GET'])
@MarshalWith(schemas.LetterProofingResponseSchema)
@require_user
def get_state(user) -> FluxData:
    current_app.logger.info('Getting proofing state for user {}'.format(user))
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn, raise_on_missing=False)

    if proofing_state:
        current_app.logger.info('Found proofing state for user {}'.format(user))
        result = check_state(proofing_state)
        return result.to_response()
    return success_response(message=LetterMsg.no_state)


@letter_proofing_views.route('/proofing', methods=['POST'])
@UnmarshalWith(schemas.LetterProofingRequestSchema)
@MarshalWith(schemas.LetterProofingResponseSchema)
@can_verify_identity
@require_user
def proofing(user: User, nin: str) -> FluxData:
    current_app.logger.info('Send letter for user {} initiated'.format(user))
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn, raise_on_missing=False)

    # No existing proofing state was found, create a new one
    if not proofing_state:
        # Create a LetterNinProofingUser in proofingdb
        proofing_state = create_proofing_state(user.eppn, nin)
        current_app.logger.info('Created proofing state for user {}'.format(user))

    # Add the nin used to initiate the proofing state to the user
    # NOOP if the user already have the nin
    add_nin_to_user(user, proofing_state)

    # TODO: Don't send a letter if the nin is already verified

    if proofing_state.proofing_letter.is_sent:
        current_app.logger.info('A letter has already been sent to the user. ')
        current_app.logger.debug('Proofing state: {}'.format(proofing_state.to_dict()))
        result = check_state(proofing_state)
        if result.error:
            # error message
            return result.to_response()
        if not result.is_expired:
            return result.to_response()
        # XXX Are we sure that the user wants to send a new letter?
        current_app.logger.info('The letter has expired. Sending a new one...')
    try:
        address = get_address(user, proofing_state)
        if not address:
            current_app.logger.error('No address found for user {}'.format(user))
            return error_response(message=LetterMsg.address_not_found)
    except MsgTaskFailed:
        current_app.logger.exception(f'Navet lookup failed for user {user}')
        current_app.stats.count('navet_error')
        return error_response(message=CommonMsg.navet_error)

    # Set and save official address
    proofing_state.proofing_letter.address = address
    current_app.proofing_statedb.save(proofing_state)

    try:
        campaign_id = send_letter(user, proofing_state)
        current_app.stats.count('letter_sent')
    except pdf.AddressFormatException:
        current_app.logger.exception('Failed formatting address')
        current_app.stats.count('address_format_error')
        return error_response(message=LetterMsg.bad_address)
    except EkopostException:
        current_app.logger.exception('Ekopost returned an error')
        current_app.stats.count('ekopost_error')
        return error_response(message=CommonMsg.temp_problem)

    # Save the users proofing state
    proofing_state.proofing_letter.transaction_id = campaign_id
    proofing_state.proofing_letter.is_sent = True
    proofing_state.proofing_letter.sent_ts = True
    current_app.proofing_statedb.save(proofing_state)
    result = check_state(proofing_state)
    result.message = LetterMsg.letter_sent
    return result.to_response()


@letter_proofing_views.route('/verify-code', methods=['POST'])
@UnmarshalWith(schemas.VerifyCodeRequestSchema)
@MarshalWith(schemas.VerifyCodeResponseSchema)
@require_user
def verify_code(user: User, code: str) -> FluxData:
    current_app.logger.info('Verifying code for user {}'.format(user))
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn, raise_on_missing=False)

    if not proofing_state:
        return error_response(message=LetterMsg.no_state)

    # Check if provided code matches the one in the letter
    if not code == proofing_state.nin.verification_code:
        current_app.logger.error('Verification code for user {} does not match'.format(user))
        # TODO: Throttling to discourage an adversary to try brute force
        return error_response(message=LetterMsg.wrong_code)

    state_info = check_state(proofing_state)
    if state_info.error:
        return state_info.to_response()

    if state_info.is_expired:
        # This is not an error in the get_state view, but here it is an error so 'upgrade' it.
        state_info.error = True
        return state_info.to_response()

    try:
        # Fetch registered address again, to save the address of record at time of verification.
        official_address = get_address(user, proofing_state)
    except MsgTaskFailed:
        current_app.logger.exception(f'Navet lookup failed for user {user}')
        current_app.stats.count('navet_error')
        return error_response(message=CommonMsg.navet_error)

    proofing_log_entry = LetterProofing(
        user,
        created_by='eduid_letter_proofing',
        nin=proofing_state.nin.number,
        letter_sent_to=proofing_state.proofing_letter.address,
        transaction_id=proofing_state.proofing_letter.transaction_id,
        user_postal_address=official_address,
        proofing_version='2016v1',
    )
    try:
        # Verify nin for user
        proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
        if not verify_nin_for_user(proofing_user, proofing_state, proofing_log_entry):
            current_app.logger.error(f'Failed verifying NIN for user {user}')
            return error_response(message=CommonMsg.temp_problem)
        current_app.logger.info(f'Verified code for user {user}')
        # Remove proofing state
        current_app.proofing_statedb.remove_state(proofing_state)
        current_app.stats.count(name='nin_verified')
        return success_response(
            payload=dict(nins=proofing_user.nins.to_list_of_dicts()), message=LetterMsg.verify_success
        )
    except AmTaskFailed:
        current_app.logger.exception(f'Verifying nin for user {user} failed')
        return error_response(message=CommonMsg.temp_problem)


@letter_proofing_views.route('/get-code', methods=['GET'])
@require_user
def get_code(user):
    """
    Backdoor to get the verification code in the staging or dev environments
    """
    try:
        if check_magic_cookie(current_app.config):
            state = current_app.proofing_statedb.get_state_by_eppn(user.eppn)
            return state.nin.verification_code
    except Exception:
        current_app.logger.exception(f"{user} tried to use the backdoor to get the letter verification code for a NIN")
    abort(400)
