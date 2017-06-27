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

import datetime
from flask import Blueprint, session, abort
from flask import current_app

from eduid_userdb.element import PrimaryElementViolation, DuplicateElementViolation
from eduid_userdb.exceptions import UserOutOfSync
from eduid_userdb.phone import PhoneNumber
from eduid_common.api.decorators import MarshalWith, UnmarshalWith
from eduid_webapp.phone.helpers import save_user, require_user
from eduid_webapp.phone.schemas import PhoneListPayload, SimplePhoneSchema, PhoneSchema, PhoneResponseSchema
from eduid_webapp.phone.schemas import VerificationCodeSchema
from eduid_webapp.phone.verifications import send_verification_code


phone_views = Blueprint('phone', __name__, url_prefix='', template_folder='templates')


@phone_views.route('/all', methods=['GET'])
@MarshalWith(PhoneResponseSchema)
@require_user
def get_all_phones(user):
    '''
    view to get a listing of all phones for the logged in user.
    '''
    csrf_token = session.get_csrf_token()
    phones = {'phones': user.phone_numbers.to_list_of_dicts(),
              'csrf_token': csrf_token}
    return PhoneListPayload().dump(phones).data


@phone_views.route('/new', methods=['POST'])
@UnmarshalWith(PhoneSchema)
@MarshalWith(PhoneResponseSchema)
@require_user
def post_phone(user, number, verified, primary, csrf_token):
    '''
    view to add a new phone to the user data of the currently
    logged in user.

    Returns a listing of  all phones for the logged in user.
    '''
    if session.get_csrf_token() != csrf_token:
        abort(400)

    current_app.logger.debug('Trying to save unconfirmed mobile {!r} '
                             'for user {!r}'.format(number, user))

    new_phone = PhoneNumber(number=number, application='dashboard',
                            verified=False, primary=False)

    try:
        user.phone_numbers.add(new_phone)
    except DuplicateElementViolation:
        return {
            '_status': 'error',
            'error': {'form': 'phone_duplicated'}
        }

    try:
        save_user(user)
    except UserOutOfSync:
        current_app.logger.debug('Couldnt save mobile {!r} for user {!r}, '
                                 'data out of sync'.format(number, user))
        return {
            '_status': 'error',
            'error': {'form': 'out_of_sync'}
        }

    current_app.logger.info('Saved unconfirmed mobile {!r} '
                            'for user {!r}'.format(number, user))
    current_app.stats.count(name='mobile_save_unconfirmed_mobile', value=1)

    send_verification_code(user, number)
    current_app.stats.count(name='mobile_send_verification_code', value=1)

    phones = {'phones': user.phone_numbers.to_list_of_dicts()}
    return PhoneListPayload().dump(phones).data


@phone_views.route('/primary', methods=['POST'])
@UnmarshalWith(SimplePhoneSchema)
@MarshalWith(PhoneResponseSchema)
@require_user
def post_primary(user, number, csrf_token):
    '''
    view to mark one of the (verified) phone numbers of the logged in user
    as the primary phone number.

    Returns a listing of  all phones for the logged in user.
    '''
    if session.get_csrf_token() != csrf_token:
        abort(400)
    current_app.logger.debug('Trying to save mobile {!r} as primary '
                             'for user {!r}'.format(number, user))

    try:
        phone_element = user.phone_numbers.find(number)
    except IndexError:
        current_app.logger.debug('Couldnt save mobile {!r} as primary for user'
                                 ' {!r}, data out of sync'.format(number, user))
        return {
            '_status': 'error',
            'error': {'form': 'out_of_sync'}
        }

    if not phone_element.is_verified:
        current_app.logger.debug('Couldnt save mobile {!r} as primary for user'
                                 ' {!r}, mobile unconfirmed'.format(number, user))
        return {
            '_status': 'error',
            'error': {'form': 'phones.unconfirmed_number_not_primary'}
        }

    user.phone_numbers.primary = phone_element.number
    try:
        save_user(user)
    except UserOutOfSync:
        current_app.logger.debug('Couldnt save mobile {!r} as primary for user'
                                 ' {!r}, data out of sync'.format(number, user))
        return {
            '_status': 'error',
            'error': {'form': 'out_of_sync'}
        }
    current_app.logger.info('Mobile {!r} made primary '
                            'for user {!r}'.format(number, user))
    current_app.stats.count(name='mobile_set_primary', value=1)

    phones = {'phones': user.phone_numbers.to_list_of_dicts()}
    return PhoneListPayload().dump(phones).data


def _steal_phone(number):
    previous_user = current_app.phone_proofing_userdb.get_user_by_phone(number,
            raise_on_missing=False)
    if previous_user and previous_user.phone_numbers.primary and \
            previous_user.phone_numbers.primary.number == number:
        # Promote some previous_user verified phone number to primary
        for phone_number in previous_user.phone_numbers.to_list():
            if phone_number.is_verified and phone_number.number != number:
                previous_user.phone_numbers.primary = phone_number.number
                break
        previous_user.phone_numbers.remove(number)
        save_user(previous_user)


@phone_views.route('/verify', methods=['POST'])
@UnmarshalWith(VerificationCodeSchema)
@MarshalWith(PhoneResponseSchema)
@require_user
def verify(user, code, number, csrf_token):
    '''
    view to mark one of the (unverified) phone numbers of the logged in user
    as verified.

    Returns a listing of  all phones for the logged in user.
    '''
    if session.get_csrf_token() != csrf_token:
        abort(400)
    current_app.logger.debug('Trying to save mobile {!r} as verified '
                             'for user {!r}'.format(number, user))

    db = current_app.verifications_db
    state = db.get_state_by_eppn_and_mobile(user.eppn, number)

    timeout = current_app.config.get('PHONE_VERIFICATION_TIMEOUT', 24)
    if state.is_expired(timeout):
        msg = "Verification code is expired: {!r}".format(state.verification)
        current_app.logger.debug(msg)
        return {
            '_status': 'error',
            'error': {'form': 'phones.code_expired'}
        }

    if code != state.verification.verification_code:
        msg = "Invalid verification code: {!r}".format(state.verification)
        current_app.logger.debug(msg)
        return {
            '_status': 'error',
            'error': {'form': 'phones.code_invalid'}
        }

    current_app.verifications_db.remove_state(state)

    _steal_phone(number)

    new_phone = PhoneNumber(number = number, application = 'dashboard',
                            verified = True, primary = False)

    if user.phone_numbers.primary is None:
        new_phone.is_primary = True
    try:
        user.phone_numbers.add(new_phone)
    except DuplicateElementViolation:
        user.phone_numbers.find(number).is_verified = True
        if user.phone_numbers.primary is None:
            user.phone_numbers.find(number).is_primary = True

    try:
        save_user(user)
    except UserOutOfSync:
        current_app.logger.debug('Couldnt confirm mobile {!r} for user'
                                 ' {!r}, data out of sync'.format(number, user))
        return {
            '_status': 'error',
            'error': {'form': 'out_of_sync'}
        }
    current_app.logger.info('Mobile {!r} confirmed '
                            'for user {!r}'.format(number, user))
    current_app.stats.count(name='mobile_verify_success', value=1)

    phones = {'phones': user.phone_numbers.to_list_of_dicts()}
    return PhoneListPayload().dump(phones).data


@phone_views.route('/remove', methods=['POST'])
@UnmarshalWith(SimplePhoneSchema)
@MarshalWith(PhoneResponseSchema)
@require_user
def post_remove(user, number, csrf_token):
    '''
    view to remove one of the phone numbers of the logged in user.

    Returns a listing of  all phones for the logged in user.
    '''
    if session.get_csrf_token() != csrf_token:
        abort(400)

    current_app.logger.debug('Trying to remove mobile {!r} '
                             'from user {!r}'.format(number, user))

    phones = user.phone_numbers.to_list()
    if len(phones) == 1:
        msg = "Cannot remove unique mobile: {!r}".format(number)
        current_app.logger.debug(msg)
        return {
            '_status': 'error',
            'error': {'form': 'phones.cannot_remove_unique'}
        }

    try:
        user.phone_numbers.remove(number)
    except PrimaryElementViolation:
        new_index = 1 if phones[0].number == number else 0
        user.phone_numbers.primary = phones[new_index].number
        user.phone_numbers.remove(number)

    try:
        save_user(user)
    except UserOutOfSync:
        current_app.logger.debug('Couldnt remove mobile {!r} for user'
                                 ' {!r}, data out of sync'.format(number, user))
        return {
            '_status': 'error',
            'error': {'form': 'out_of_sync'}
        }

    current_app.logger.info('Mobile {!r} removed '
                            'for user {!r}'.format(number, user))
    current_app.stats.count(name='mobile_remove_success', value=1)

    phones = {'phones': user.phone_numbers.to_list_of_dicts()}
    return PhoneListPayload().dump(phones).data


@phone_views.route('/resend-code', methods=['POST'])
@UnmarshalWith(SimplePhoneSchema)
@MarshalWith(PhoneResponseSchema)
@require_user
def resend_code(user, number, csrf_token):
    '''
    view to resend a new verification code for one of the (unverified)
    phone numbers of the logged in user. 

    Returns a listing of  all phones for the logged in user.
    '''
    if session.get_csrf_token() != csrf_token:
        abort(400)

    current_app.logger.debug('Trying to send new verification code for mobile '
                             ' {!r} for user {!r}'.format(number, user))

    if not user.phone_numbers.find(number):
        current_app.logger.warning('Unknown phone in resend_code_action, user {!s}'.format(user))
        return {
            '_status': 'error',
            'error': {'form': 'out_of_sync'}
        }

    send_verification_code(user, number)
    current_app.logger.debug('New verification code sended to '
                             'mobile {!r} for user {!r}'.format(number, user))
    current_app.stats.count(name='mobile_resend_code', value=1)

    phones = {'phones': user.phone_numbers.to_list_of_dicts()}
    return PhoneListPayload().dump(phones).data
