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

import time

from eduid_common.api.utils import get_short_hash, save_and_sync_user
from eduid_userdb.element import DuplicateElementViolation
from eduid_userdb.logs import PhoneNumberProofing
from eduid_userdb.phone import PhoneNumber
from eduid_userdb.proofing import PhoneProofingElement, PhoneProofingState

from eduid_webapp.phone.app import current_phone_app as current_app


def new_proofing_state(phone, user):
    old_state = current_app.proofing_statedb.get_state_by_eppn_and_mobile(user.eppn, phone, raise_on_missing=False)
    if old_state is not None:
        now = int(time.time())
        if int(old_state.modified_ts.timestamp()) > now - current_app.config.throttle_resend_seconds:
            return None
        current_app.logger.debug('removing old proofing state: {!r}.'.format(old_state.to_dict()))
        current_app.proofing_statedb.remove_state(old_state)

    verification = PhoneProofingElement.from_dict(
        dict(number=phone, verification_code=get_short_hash(), created_by='phone')
    )
    proofing_state = PhoneProofingState(id=None, modified_ts=None, eppn=user.eppn, verification=verification)
    # XXX This should be an atomic transaction together with saving
    # the user and sending the letter.
    current_app.proofing_statedb.save(proofing_state)
    current_app.logger.info(
        'Created new phone number verification code for user {} and phone number {}.'.format(user, phone)
    )
    current_app.logger.debug('Proofing state: {!r}.'.format(proofing_state.to_dict()))
    return proofing_state


def send_verification_code(user, phone):

    state = new_proofing_state(phone, user)
    if state is None:
        return False

    current_app.msg_relay.phone_validator(state.reference, phone, state.verification.verification_code, user.language)
    current_app.logger.info('Sent verification sms to user {} with phone number {}.'.format(user, phone))
    return True


def verify_phone_number(state, proofing_user):
    """
    :param proofing_user: ProofingUser
    :param state: Phone proofing state

    :type proofing_user: eduid_userdb.proofing.ProofingUser
    :type state: PhoneProofingState

    :return: None

    """
    number = state.verification.number
    new_phone = PhoneNumber.from_dict(dict(number=number, created_by='eduid_phone', verified=True, primary=False))

    has_primary = proofing_user.phone_numbers.primary
    if has_primary is None:
        new_phone.is_primary = True
    try:
        proofing_user.phone_numbers.add(new_phone)
    except DuplicateElementViolation:
        proofing_user.phone_numbers.find(number).is_verified = True
        if has_primary is None:
            proofing_user.phone_numbers.find(number).is_primary = True

    phone_number_proofing = PhoneNumberProofing(
        proofing_user,
        created_by='phone',
        phone_number=state.verification.number,
        reference=state.reference,
        proofing_version='2013v1',
    )
    if current_app.proofing_log.save(phone_number_proofing):
        save_and_sync_user(proofing_user)
        current_app.logger.info('Mobile {} confirmed ' 'for user {}'.format(number, proofing_user))
        current_app.stats.count(name='mobile_verify_success', value=1)
        current_app.proofing_statedb.remove_state(state)
        current_app.logger.debug('Removed proofing state: {} '.format(state))
