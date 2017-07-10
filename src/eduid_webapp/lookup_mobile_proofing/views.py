# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Blueprint, current_app

from eduid_common.api.decorators import require_user, can_verify_identity, MarshalWith, UnmarshalWith
from eduid_common.api.helpers import add_nin_to_user, verify_nin_for_user
from eduid_common.api.exceptions import MsgTaskFailed, AmTaskFailed
from eduid_common.api.schemas.csrf import CSRFResponse
from eduid_webapp.lookup_mobile_proofing import schemas
from eduid_webapp.lookup_mobile_proofing.helpers import create_proofing_state, match_mobile_to_user
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
    current_app.logger.info('Trying to verify nin via mobile number for user {!r}.'.format(user))
    current_app.logger.debug('NIN: {!s}.'.format(nin))

    # Add nin as not verified to the user
    proofing_state = create_proofing_state(user, nin)
    add_nin_to_user(user, proofing_state)

    # Get list of verified mobile numbers
    verified_mobiles = [item.number for item in user.phone_numbers.to_list() if item.is_verified]
    if not verified_mobiles:
        return {'_status': 'error', 'error': 'no_phone'}

    try:
        success, proofing_log_entry = match_mobile_to_user(user, nin, verified_mobiles)
    except LookupMobileTaskFailed:
        current_app.stats.count('validate_nin_by_mobile_error')
        return {'_status': 'error', 'error': 'error_lookup_mobile_task'}
    except MsgTaskFailed:
        current_app.stats.count('navet_error')
        return {'_status': 'error', 'error': 'error_navet_task'}

    if success:
        try:
            # Verify nin for user
            verify_nin_for_user(user, proofing_state, proofing_log_entry)
            return {'success': True}
        except AmTaskFailed as e:
            current_app.logger.error('Verifying nin for user {} failed'.format(user))
            current_app.logger.error('{}'.format(e))
            return {'_status': 'error', 'error': 'technical_problems'}

    return {'success': False, 'message': 'no_match'}
