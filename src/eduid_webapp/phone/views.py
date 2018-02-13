# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

from __future__ import absolute_import

from flask import Blueprint, session
from flask import current_app

from eduid_userdb.element import PrimaryElementViolation, DuplicateElementViolation
from eduid_userdb.exceptions import UserOutOfSync
from eduid_userdb.phone import PhoneNumber
from eduid_userdb.proofing import ProofingUser
from eduid_common.api.decorators import require_user, MarshalWith, UnmarshalWith
from eduid_common.api.utils import save_and_sync_user
from eduid_webapp.phone.schemas import PhoneListPayload, SimplePhoneSchema, PhoneSchema, PhoneResponseSchema
from eduid_webapp.phone.schemas import VerificationCodeSchema
from eduid_webapp.phone.verifications import send_verification_code, verify_phone_number


phone_views = Blueprint('phone', __name__, url_prefix='', template_folder='templates')


@phone_views.route('/all', methods=['GET'])
@MarshalWith(PhoneResponseSchema)
@require_user
def get_all_phones(user):
    """
    view to get a listing of all phones for the logged in user.
    """

    phones = {
        'phones': user.phone_numbers.to_list_of_dicts()
    }
    return PhoneListPayload().dump(phones).data


@phone_views.route('/new', methods=['POST'])
@UnmarshalWith(PhoneSchema)
@MarshalWith(PhoneResponseSchema)
@require_user
def post_phone(user, number, verified, primary):
    """
    view to add a new phone to the user data of the currently
    logged in user.

    Returns a listing of  all phones for the logged in user.
    """
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    current_app.logger.debug('Trying to save unconfirmed mobile {!r} '
                             'for user {!r}'.format(number, proofing_user))

    new_phone = PhoneNumber(number=number, application='phone',
                            verified=False, primary=False)
    proofing_user.phone_numbers.add(new_phone)

    try:
        save_and_sync_user(proofing_user)
    except UserOutOfSync:
        current_app.logger.debug('Couldnt save mobile {!r} for user {!r}, '
                                 'data out of sync'.format(number, proofing_user))
        return {
            '_status': 'error',
            'message': 'user-out-of-sync'
        }

    current_app.logger.info('Saved unconfirmed mobile {!r} '
                            'for user {!r}'.format(number, proofing_user))
    current_app.stats.count(name='mobile_save_unconfirmed_mobile', value=1)

    send_verification_code(proofing_user, number)
    current_app.stats.count(name='mobile_send_verification_code', value=1)

    phones = {
            'phones': proofing_user.phone_numbers.to_list_of_dicts(),
            'message': 'phones.save-success'
            }
    return PhoneListPayload().dump(phones).data


@phone_views.route('/primary', methods=['POST'])
@UnmarshalWith(SimplePhoneSchema)
@MarshalWith(PhoneResponseSchema)
@require_user
def post_primary(user, number):
    """
    view to mark one of the (verified) phone numbers of the logged in user
    as the primary phone number.

    Returns a listing of  all phones for the logged in user.
    """
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    current_app.logger.debug('Trying to save mobile {!r} as primary '
                             'for user {!r}'.format(number, proofing_user))

    try:
        phone_element = proofing_user.phone_numbers.find(number)
    except IndexError:
        current_app.logger.debug('Couldnt save mobile {!r} as primary for user'
                                 ' {!r}, data out of sync'.format(number, proofing_user))
        return {
            '_status': 'error',
            'message': 'user-out-of-sync'
        }

    if not phone_element.is_verified:
        current_app.logger.debug('Couldnt save mobile {!r} as primary for user'
                                 ' {!r}, mobile unconfirmed'.format(number, proofing_user))
        return {
            '_status': 'error',
            'message': 'phones.unconfirmed_number_not_primary'
        }

    proofing_user.phone_numbers.primary = phone_element.number
    try:
        save_and_sync_user(proofing_user)
    except UserOutOfSync:
        current_app.logger.debug('Couldnt save mobile {!r} as primary for user'
                                 ' {!r}, data out of sync'.format(number, proofing_user))
        return {
            '_status': 'error',
            'message': 'user-out-of-sync'
        }
    current_app.logger.info('Mobile {!r} made primary '
                            'for user {!r}'.format(number, proofing_user))
    current_app.stats.count(name='mobile_set_primary', value=1)

    phones = {
            'phones': proofing_user.phone_numbers.to_list_of_dicts(),
            'message': 'phones.primary-success'
            }
    return PhoneListPayload().dump(phones).data


@phone_views.route('/verify', methods=['POST'])
@UnmarshalWith(VerificationCodeSchema)
@MarshalWith(PhoneResponseSchema)
@require_user
def verify(user, code, number):
    """
    view to mark one of the (unverified) phone numbers of the logged in user
    as verified.

    Returns a listing of  all phones for the logged in user.
    """
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    current_app.logger.debug('Trying to save mobile {!r} as verified '
                             'for user {!r}'.format(number, proofing_user))

    db = current_app.proofing_statedb
    state = db.get_state_by_eppn_and_mobile(proofing_user.eppn, number,
            raise_on_missing=False)
    if state is not None:
        current_app.logger.debug('Invalid verification code for phone {!r}'
                                 ' for user {!r}'.format(number, proofing_user))
        return {
            '_status': 'error',
            'message': 'phones.code_invalid'
        }

    timeout = current_app.config.get('PHONE_VERIFICATION_TIMEOUT')
    if state.is_expired(timeout):
        msg = "Verification code is expired: {!r}".format(state.verification)
        current_app.logger.debug(msg)
        return {
            '_status': 'error',
            'message': 'phones.code_expired_send_new'
        }
    if code != state.verification.verification_code:
        msg = "Invalid verification code: {!r}".format(state.verification)
        current_app.logger.debug(msg)
        return {
            '_status': 'error',
            'message': 'phones.code_invalid'
        }
    try:
        verify_phone_number(state, proofing_user)
        current_app.logger.info('phone number {!r} successfully verified'
                                 ' for user {!r}'.format(number, proofing_user))
        phones = {
                'phones': proofing_user.phone_numbers.to_list_of_dicts(),
                'message': 'phones.verification-success'
                }
        return PhoneListPayload().dump(phones).data
    except UserOutOfSync:
        current_app.logger.debug('Couldnt confirm mobile {!r} for user'
                                 ' {!r}, data out of sync'.format(number, proofing_user))
        return {
            '_status': 'error',
            'message': 'user-out-of-sync'
        }


@phone_views.route('/remove', methods=['POST'])
@UnmarshalWith(SimplePhoneSchema)
@MarshalWith(PhoneResponseSchema)
@require_user
def post_remove(user, number):
    """
    view to remove one of the phone numbers of the logged in user.

    Returns a listing of  all phones for the logged in user.
    """
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    current_app.logger.debug('Trying to remove mobile {!r} '
                             'from user {!r}'.format(number, proofing_user))

    try:
        proofing_user.phone_numbers.remove(number)
    except PrimaryElementViolation:
        verified = proofing_user.phone_numbers.verified.to_list()
        new_index = 1 if verified[0].number == number else 0
        proofing_user.phone_numbers.primary = verified[new_index].number
        proofing_user.phone_numbers.remove(number)

    try:
        save_and_sync_user(proofing_user)
    except UserOutOfSync:
        current_app.logger.debug('Couldnt remove mobile {!r} for user'
                                 ' {!r}, data out of sync'.format(number, proofing_user))
        return {
            '_status': 'error',
            'message': 'user-out-of-sync'
        }
    current_app.logger.info('Mobile {!r} removed '
                            'for user {!r}'.format(number, proofing_user))
    current_app.stats.count(name='mobile_remove_success', value=1)

    phones = {
            'phones': proofing_user.phone_numbers.to_list_of_dicts(),
            'message': 'phones.removal-success'
            }
    return PhoneListPayload().dump(phones).data


@phone_views.route('/resend-code', methods=['POST'])
@UnmarshalWith(SimplePhoneSchema)
@MarshalWith(PhoneResponseSchema)
@require_user
def resend_code(user, number):
    """
    view to resend a new verification code for one of the (unverified)
    phone numbers of the logged in user. 

    Returns a listing of  all phones for the logged in user.
    """
    current_app.logger.debug('Trying to send new verification code for mobile '
                             ' {!r} for user {!r}'.format(number, user))

    if not user.phone_numbers.find(number):
        current_app.logger.warning('Unknown phone in resend_code_action, user {!s}'.format(user))
        return {
            '_status': 'error',
            'message': 'user-out-of-sync'
        }

    send_verification_code(user, number)
    current_app.logger.debug('New verification code sended to '
                             'mobile {!r} for user {!r}'.format(number, user))
    current_app.stats.count(name='mobile_resend_code', value=1)

    phones = {
            'phones': user.phone_numbers.to_list_of_dicts(),
            'message': 'phones.code-sent'
            }
    return PhoneListPayload().dump(phones).data
