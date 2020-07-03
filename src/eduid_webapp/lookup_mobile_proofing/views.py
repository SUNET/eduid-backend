# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Blueprint

from eduid_common.api.decorators import MarshalWith, UnmarshalWith, can_verify_identity, require_user
from eduid_common.api.exceptions import AmTaskFailed, MsgTaskFailed
from eduid_common.api.helpers import add_nin_to_user, verify_nin_for_user
from eduid_common.api.messages import CommonMsg, error_response
from eduid_common.api.schemas.csrf import CSRFResponse

from eduid_webapp.lookup_mobile_proofing import schemas
from eduid_webapp.lookup_mobile_proofing.app import current_mobilep_app as current_app
from eduid_webapp.lookup_mobile_proofing.helpers import MobileMsg, create_proofing_state, match_mobile_to_user
from eduid_webapp.lookup_mobile_proofing.lookup_mobile_relay import LookupMobileTaskFailed

__author__ = 'lundberg'

mobile_proofing_views = Blueprint('lookup_mobile_proofing', __name__, url_prefix='', template_folder='templates')


@mobile_proofing_views.route('/proofing', methods=['GET'])
@MarshalWith(CSRFResponse)
@require_user
def get_state(user):
    return {}


@mobile_proofing_views.route('/proofing', methods=['POST'])
@UnmarshalWith(schemas.LookupMobileProofingRequestSchema)
@MarshalWith(schemas.LookupMobileProofingResponseSchema)
@can_verify_identity
@require_user
def proofing(user, nin):
    current_app.logger.info('Trying to verify nin via mobile number for user {}.'.format(user))
    current_app.logger.debug('NIN: {!s}.'.format(nin))

    # Add nin as not verified to the user
    proofing_state = create_proofing_state(user, nin)
    add_nin_to_user(user, proofing_state)

    # Get list of verified mobile numbers
    verified_mobiles = [item.number for item in user.phone_numbers.to_list() if item.is_verified]
    if not verified_mobiles:
        return error_response(message=MobileMsg.no_phone)

    try:
        success, proofing_log_entry = match_mobile_to_user(user, nin, verified_mobiles)
    except LookupMobileTaskFailed:
        current_app.stats.count('validate_nin_by_mobile_error')
        return error_response(message=MobileMsg.lookup_error)
    except MsgTaskFailed:
        current_app.stats.count('navet_error')
        return error_response(message=CommonMsg.navet_error)

    if success:
        try:
            # Verify nin for user
            if not verify_nin_for_user(user, proofing_state, proofing_log_entry):
                return error_response(message=CommonMsg.temp_problem)
            return {'success': True, 'message': str(MobileMsg.verify_success.value)}
        except AmTaskFailed:
            current_app.logger.exception(f'Verifying nin for user {user} failed')
            return error_response(message=CommonMsg.temp_problem)

    return error_response(message=MobileMsg.no_match)
