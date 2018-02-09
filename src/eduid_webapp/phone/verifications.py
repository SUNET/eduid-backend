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

from datetime import datetime
from flask import current_app

from eduid_common.api.utils import get_short_hash
from eduid_common.api.utils import save_and_sync_user
from eduid_userdb.element import DuplicateElementViolation
from eduid_userdb.proofing import PhoneProofingElement, PhoneProofingState
from eduid_userdb.phone import PhoneNumber


def new_verification_code(phone, user):
    old_verification = current_app.proofing_statedb.get_state_by_eppn_and_mobile(
                       user.eppn, phone, raise_on_missing=False)
    if old_verification is not None:
        current_app.logger.debug('removing old verification code:'
                                 ' {!r}.'.format(old_verification.to_dict()))
        current_app.proofing_statedb.remove_state(old_verification)

    code = get_short_hash()
    verification = PhoneProofingElement(phone=phone,
                                        verification_code=code,
                                        application='phone')
    verification_data = {
        'eduPersonPrincipalName': user.eppn,
        'verification': verification.to_dict()
        }
    verification_state = PhoneProofingState(verification_data)
    # XXX This should be an atomic transaction together with saving
    # the user and sending the letter.
    current_app.proofing_statedb.save(verification_state)
    current_app.logger.info('Created new mobile verification code '
                            'for user {!r} and mobile {!r}.'.format(user, phone))
    current_app.logger.debug('Verification Code:'
                             ' {!r}.'.format(verification_state.to_dict()))
    return code, str(verification_state.to_dict()['_id'])


def send_verification_code(user, phone):

    code, reference = new_verification_code(phone, user)

    current_app.msg_relay.phone_validator(reference, phone, code, user.language)
    current_app.logger.info("Sent verification sms to user {!r}"
                            " with phone number {!s}.".format(user, phone))

    
def verify_phone_number(state, proofing_user):
    """
    :param proofing_user: ProofingUser
    :param state: Phone proofing state

    :type proofing_user: eduid_userdb.proofing.ProofingUser
    :type state: PhoneProofingState

    :return: None

    """
    number = state.verification.number
    new_phone = PhoneNumber(number = number, application = 'eduid_phone',
                            verified = True, primary = False)

    has_primary = proofing_user.phone_numbers.primary
    if has_primary is None:
        new_phone.is_primary = True
    try:
        proofing_user.phone_numbers.add(new_phone)
    except DuplicateElementViolation:
        proofing_user.phone_numbers.find(number).is_verified = True
        if has_primary is None:
            proofing_user.phone_numbers.find(number).is_primary = True

    save_and_sync_user(proofing_user)
    current_app.logger.info('Mobile {!r} confirmed '
                            'for user {!r}'.format(number, proofing_user))
    current_app.stats.count(name='mobile_verify_success', value=1)
    current_app.proofing_statedb.remove_state(state)
    current_app.logger.debug('Removed proofing state: {} '.format(state))


# XXX remove when dumping old dashboard
def old_verify_phone_number(number, verification, proofing_user):
    """
    :param proofing_user: ProofingUser
    :param state: E-mail proofing state

    :type proofing_user: eduid_userdb.proofing.ProofingUser
    :type state: EmailProofingState

    :return: None

    """
    new_phone = PhoneNumber(number = number, application = 'eduid_phone',
                            verified = True, primary = False)

    has_primary = proofing_user.phone_numbers.primary
    if has_primary is None:
        new_phone.is_primary = True
    try:
        proofing_user.phone_numbers.add(new_phone)
    except DuplicateElementViolation:
        proofing_user.phone_numbers.find(number).is_verified = True
        if has_primary is None:
            proofing_user.phone_numbers.find(number).is_primary = True

    save_and_sync_user(proofing_user)
    current_app.logger.info('Mobile {!r} confirmed '
                            'for user {!r}'.format(number, proofing_user))
    current_app.stats.count(name='mobile_verify_success', value=1)
    verified = {
        'verified': True,
        'verified_timestamp': datetime.utcnow()
    }
    verification.update(verified)
    current_app.old_dashboard_db.verifications.update({'_id': verification['_id']}, verification)
    current_app.logger.debug('Updated verification: {!r} '.format(verification))
# XXX end remove when dumping old dashboard


def steal_verified_phone(user, number):
    old_user = current_app.central_userdb.get_user_by_phone(number,
            raise_on_missing=False)
    if old_user and old_user.user_id != user.user_id:
        current_app.logger.debug('Found old user {!r} with phone number ({!s})'
                                 ' already verified.'.format(old_user, number))
        current_app.logger.debug('Old user phone numbers BEFORE: '
                                 '{!r}.'.format(old_user.phone_numbers.to_list()))
        if old_user.phone_numbers.primary.number == number:
            # Promote some other verified phone number to primary
            for other_phone in old_user.phone_numbers.verified.to_list():
                if other_phone.number != number:
                    user.phone_numbers.primary = other_phone.number
                    break
        old_user.phone_numbers.remove(number)
        current_app.logger.debug('Old user phone numbers AFTER: '
                                 '{!r}.'.format(old_user.phone_numbers.to_list()))
        save_and_sync_user(old_user)
        current_app.logger.info('Removed phone number {!r} from user {!r}.'.format(number, old_user))
        current_app.stats.count('verify_mobile_stolen', 1)

