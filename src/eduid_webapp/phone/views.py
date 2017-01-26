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

from flask import Blueprint
from flask import render_template, current_app

from eduid_userdb.exceptions import UserOutOfSync
from eduid_userdb.phone import PhoneNumber
from eduid_common.api.decorators import require_dashboard_user, MarshalWith, UnmarshalWith
from eduid_common.api.utils import save_dashboard_user
from eduid_webapp.phone.schemas import PhoneListPayload, PhoneSchema, PhoneResponseSchema
from eduid_webapp.phone.schemas import VerificationCodeSchema
from eduid_webapp.phone.verifications import send_verification_code


phone_views = Blueprint('phone', __name__, url_prefix='', template_folder='templates')


@phone_views.route('/all', methods=['GET'])
@MarshalWith(PhoneResponseSchema)
@require_dashboard_user
def get_all_phones(user):
    phones = {'phones': user.phone_numbers.to_list_of_dicts()}
    return PhoneListPayload().dump(phones).data


@phone_views.route('/new', methods=['POST'])
@UnmarshalWith(PhoneSchema)
@MarshalWith(PhoneResponseSchema)
@require_dashboard_user
def post_phone(user, phone, confirmed, primary):
    new_phone = PhoneNumber(phone=phone, application='dashboard',
                           verified=False, primary=False)
    user.phone_numbers.add(new_phone)
    try:
        save_dashboard_user(user, dbattr_name='dashboard_userdb')
    except UserOutOfSync:
        return {
            '_status': 'error',
            'error': {'form': 'out_of_sync'}
        }

    send_verification_code(phone, user)

    phones = {'phones': user.phone_numbers.to_list_of_dicts()}
    return PhoneListPayload().dump(phones).data


@phone_views.route('/primary', methods=['POST'])
@UnmarshalWith(PhoneSchema)
@MarshalWith(PhoneResponseSchema)
@require_dashboard_user
def post_primary(user, phone, confirmed, primary):

    try:
        phone_el = user.phone_numbers.find(phone)
    except IndexError:
        return {
            '_status': 'error',
            'error': {'form': 'out_of_sync'}
        }

    if not phone_el.is_verified:
        return {
            '_status': 'error',
            'error': {'form': 'phones.unconfirmed_number_not_primary'}
        }

    user.phone_numbers.primary = phone_el.number
    try:
        save_dashboard_user(user, dbattr_name='dashboard_userdb')
    except UserOutOfSync:
        return {
            '_status': 'error',
            'error': {'form': 'out_of_sync'}
        }
    phones = {'phones': user.phone_numbers.to_list_of_dicts()}
    return PhoneListPayload().dump(phones).data


@phone_views.route('/verify', methods=['POST'])
@UnmarshalWith(VerificationCodeSchema)
@MarshalWith(PhoneResponseSchema)
@require_dashboard_user
def verify(user, code, phone):
    """
    """
    db = current_app.verifications_db
    state = db.get_state_by_eppn_and_code(user.eppn, code)
    verification = state.verification
    timeout = current_app.config.get('PHONE_VERIFICATION_TIMEOUT', 24)
    if state.is_expired(timeout):
        msg = "Verification code is expired: {!r}".format(verification)
        current_app.logger.debug(msg)
        return {
            '_status': 'error',
            'error': {'form': 'phones.code_expired'}
        }

    if phone != verification.phone:
        msg = "Invalid verification code: {!r}".format(verification)
        current_app.logger.debug(msg)
        return {
            '_status': 'error',
            'error': {'form': 'phones.code_invalid'}
        }

    verification.is_verified = True
    verification.verified_ts = datetime.datetime.now()
    verification.verified_by = user.eppn
    state.verification = verification
    current_app.verifications_db.save(state)

    other = current_app.dashboard_userdb.get_user_by_phone(phone,
            raise_on_missing=False)
    if other and other.phone_numbers.primary and \
            other.phone_numbers.primary.number == phone:
        # Promote some other verified phone number to primary
        for phone_number in other.phone_numbers.to_list():
            if phone_number.is_verified and phone_number.number != phone:
                other.phone_numbers.primary = phone_number.number
                break
        other.phone_numbers.remove(phone)
        save_dashboard_user(other, dbattr_name='dashboard_userdb')

    new_phone = PhoneNumber(phone = phone, application = 'dashboard',
                            verified = True, primary = False)
    if user.phone_numbers.primary is None:
        new_phone.is_primary = True
    try:
        user.phone_numbers.add(new_phone)
    except DuplicateElementViolation:
        user.phone_numbers.find(phone).is_verified = True
        if user.phone_numbers.primary is None:
            user.phone_numbers.find(phone).is_primary = True

    try:
        save_dashboard_user(user, dbattr_name='dashboard_userdb')
    except UserOutOfSync:
        return {
            '_status': 'error',
            'error': {'form': 'out_of_sync'}
        }
    phones = {'phones': user.phone_numbers.to_list_of_dicts()}
    return PhoneListPayload().dump(phones).data


@phone_views.route('/remove', methods=['POST'])
@UnmarshalWith(PhoneSchema)
@MarshalWith(PhoneResponseSchema)
@require_dashboard_user
def post_remove(user, phone, confirmed, primary):
    phones = user.phone_numbers.to_list()
    if len(phones) == 1:
        return {
            '_status': 'error',
            'error': {'form': 'phones.cannot_remove_unique'}
        }

    try:
        user.phone_numbers.remove(phone)
    except PrimaryElementViolation:
        new_index = 1 if phones[0].number == phone else 0
        user.phone_numbers.primary = phones[new_index].number
        user.phone_numbers.remove(phone)

    try:
        save_dashboard_user(user, dbattr_name='dashboard_userdb')
    except UserOutOfSync:
        return {
            '_status': 'error',
            'error': {'form': 'out_of_sync'}
        }

    phones = {'phones': user.phone_numbers.to_list_of_dicts()}
    return PhoneListPayload().dump(phones).data


@phone_views.route('/resend-code', methods=['POST'])
@UnmarshalWith(PhoneSchema)
@MarshalWith(PhoneResponseSchema)
@require_dashboard_user
def resend_code(user, phone):
    if not user.phone_numbers.find(phone):
        current_app.logger.warning('Unknown phone in resend_code_action, user {!s}'.format(user))
        return {
            '_status': 'error',
            'error': {'form': 'out_of_sync'}
        }
    
    send_verification_code(phone, user)

    phones = {'phones': user.phone_numbers.to_list_of_dicts()}
    return PhoneListPayload().dump(phones).data
