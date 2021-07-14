# -*- coding: utf-8 -*-


from flask import Blueprint

from eduid.common.rpc.lookup_mobile_relay import LookupMobileTaskFailed
from eduid.userdb import User
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, can_verify_identity, require_user
from eduid.webapp.common.api.exceptions import AmTaskFailed, MsgTaskFailed
from eduid.webapp.common.api.helpers import add_nin_to_user, verify_nin_for_user
from eduid.webapp.common.api.messages import FluxData, TranslatableMsg, error_response, success_response
from eduid.webapp.common.api.schemas.csrf import EmptyResponse
from eduid.webapp.lookup_mobile_proofing import schemas
from eduid.webapp.lookup_mobile_proofing.app import current_mobilep_app as current_app
from eduid.webapp.lookup_mobile_proofing.helpers import create_proofing_state, match_mobile_to_user

__author__ = 'lundberg'

mobile_proofing_views = Blueprint('lookup_mobile_proofing', __name__, url_prefix='', template_folder='templates')


@mobile_proofing_views.route('/proofing', methods=['GET'])
@MarshalWith(EmptyResponse)
@require_user
def get_state(user: User) -> FluxData:
    return success_response()


@mobile_proofing_views.route('/proofing', methods=['POST'])
@UnmarshalWith(schemas.LookupMobileProofingRequestSchema)
@MarshalWith(schemas.LookupMobileProofingResponseSchema)
@can_verify_identity
@require_user
def proofing(user: User, nin: str) -> FluxData:
    current_app.logger.info(f'Trying to verify nin via mobile number for user {user}.')
    current_app.logger.debug(f'NIN: {nin}.')

    # Add nin as not verified to the user
    proofing_state = create_proofing_state(user, nin)
    add_nin_to_user(user, proofing_state)

    # Get list of verified mobile numbers
    verified_mobiles = [item.number for item in user.phone_numbers.to_list() if item.is_verified]
    if not verified_mobiles:
        return error_response(message=TranslatableMsg.lookup_mobile_no_phone)

    try:
        success, proofing_log_entry = match_mobile_to_user(user, nin, verified_mobiles)
    except LookupMobileTaskFailed:
        current_app.stats.count('validate_nin_by_mobile_error')
        return error_response(message=TranslatableMsg.lookup_mobile_lookup_error)
    except MsgTaskFailed:
        current_app.stats.count('navet_error')
        return error_response(message=TranslatableMsg.navet_error)

    if success:
        try:
            # Verify nin for user
            if not verify_nin_for_user(user, proofing_state, proofing_log_entry):
                return error_response(message=TranslatableMsg.temp_problem)
            # TODO: message is letter.verification_success, this should change
            return success_response(message=TranslatableMsg.letter_proofing_verify_success)
        except AmTaskFailed:
            current_app.logger.exception(f'Verifying nin for user {user} failed')
            return error_response(message=TranslatableMsg.temp_problem)

    return error_response(message=TranslatableMsg.lookup_mobile_no_match)
