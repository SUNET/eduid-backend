# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Blueprint, current_app

from eduid_lookup_mobile.utilities import format_NIN
from eduid_common.api.decorators import require_user, can_verify_identity, MarshalWith, UnmarshalWith
from eduid_webapp.lookup_mobile_proofing import schemas
from eduid_webapp.lookup_mobile_proofing.helpers import nin_to_age

__author__ = 'lundberg'

mobile_proofing_views = Blueprint('lookup_mobile_proofing', __name__, url_prefix='', template_folder='templates')


@mobile_proofing_views.route('/proofing', methods=['POST'])
@UnmarshalWith(schemas.MobileProofingRequestSchema)
@MarshalWith(schemas.MobileProofingResponseSchema)
@can_verify_identity
@require_user
def index(user, nin):
    current_app.logger.info('Trying to verify nin via mobile number for user {!r}.'.format(user))
    current_app.logger.debug('NIN: {!s}.'.format(nin))

    # Get list of verified mobile numbers
    verified_mobiles = [x.number for x in user.phone_numbers.to_list() if x.is_verified]
    if not verified_mobiles:
        return {'_status': 'error', 'error': 'no_phone'}

    national_identity_number = format_NIN(nin)
    status = 'no_phone'
    valid_mobile = None
    registered_to_nin = None

    age = nin_to_age(national_identity_number)

    try:
        for mobile_number in verified_mobiles:
            status = 'no_match'
            # Get the registered owner of the mobile number
            registered_to_nin = current_app.lookup_mobile_relay.find_nin_by_mobile(mobile_number)
            registered_to_nin = format_NIN(registered_to_nin)

            if registered_to_nin == national_identity_number:
                # Check if registered nin was the given nin
                valid_mobile = mobile_number
                status = 'match'
                current_app.logger.info('Mobile number matched for user {!r}.'.format(user))
                current_app.logger.debug('Mobile {!s} registered to NIN: {!s}.'.format(valid_mobile, registered_to_nin))
                current_app.stats.count('validate_nin_by_mobile_exact_match')
                break
            elif registered_to_nin is not None and age < 18:
                # Check if registered nin is related to given nin
                relation = current_app.msg_relay.get_relations_to(national_identity_number, registered_to_nin)
                # FA - Fader
                # MO - Moder
                # VF - Vårdnadshavare för
                # F - Förälder
                valid_relations = ['FA', 'MO', 'VF', 'F']
                if any(r in relation for r in valid_relations):
                    valid_mobile = mobile_number
                    status = 'match_by_navet'
                    current_app.logger.info('Mobile number matched for user {!r} via navet.'.format(user))
                    current_app.logger.debug('Mobile {!s} registered to NIN: {!s}.'.format(valid_mobile,
                                                                                           registered_to_nin))
                    current_app.logger.debug('Person with NIN {!s} have relation {!s} to user: {!r}.'.format(
                        registered_to_nin, relation, user))
                    current_app.stats.count('validate_nin_by_mobile_relative_match')
                    break
    except current_app.lookup_mobile_relay.TaskFailed:
        status = 'error_lookup'
    except Exception:
        status = 'error_navet'

    msg = None
    if status == 'no_phone':
        msg = _('You have no confirmed mobile phone')
        log.info('User {!r} has no verified mobile phone number.'.format(user))
    elif status == 'no_match':
        log.info('User {!r} NIN is not associated with any verified mobile phone number.'.format(user))
        msg = _('The national identity number is not associated with a mobile for private use, see hitta.se')
        request.stats.count('validate_nin_by_mobile_no_match')
    elif status == 'error_lookup' or status == 'error_navet':
        log.error('Validate NIN via mobile failed with status "{!s}" for user {!r}.'.format(status, user))
        msg = _('Sorry, we are experiencing temporary technical '
                'problem with ${service_name}, please try again '
                'later.')
        request.stats.count('validate_nin_by_mobile_error')

    if status == 'match' or status == 'match_by_navet':
        log.info('Validate NIN via mobile succeeded with status "{!s}" for user {!r}.'.format(status, user))
        msg = _('Validate NIN via mobile with succeeded')
        user_postal_address = request.msgrelay.get_full_postal_address(national_identity_number)
        if status == 'match':
            proofing_data = TeleAdressProofing(user, status, national_identity_number, valid_mobile,
                                               user_postal_address)
        else:
            registered_postal_address = request.msgrelay.get_full_postal_address(registered_to_nin)
            proofing_data = TeleAdressProofingRelation(user, status, national_identity_number, valid_mobile,
                                                       user_postal_address, registered_to_nin, relation,
                                                       registered_postal_address)

        log.info('Logging of mobile proofing data for user {!r}.'.format(user))
        if not request.idproofinglog.log_verification(proofing_data):
            log.error('Logging of mobile proofing data for user {!r} failed.'.format(user))
            valid_mobile = None
            msg = _('Sorry, we are experiencing temporary technical '
                    'problem with ${service_name}, please try again '
                    'later.')

    validation_result = {'success': valid_mobile is not None, 'message': msg, 'mobile': valid_mobile}
    return validation_result