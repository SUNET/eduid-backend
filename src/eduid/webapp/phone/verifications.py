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

from flask import render_template

from eduid.userdb import User
from eduid.userdb.logs import PhoneNumberProofing
from eduid.userdb.phone import PhoneNumber
from eduid.userdb.proofing import PhoneProofingElement, PhoneProofingState, ProofingUser
from eduid.webapp.common.api.exceptions import MsgTaskFailed
from eduid.webapp.common.api.utils import get_short_hash, save_and_sync_user
from eduid.webapp.phone.app import current_phone_app as current_app


class SMSThrottleException(Exception):
    pass


def get_new_proofing_state(user: User, phone: str) -> PhoneProofingState:
    existing_state = current_app.proofing_statedb.get_state_by_eppn_and_mobile(user.eppn, phone)
    if existing_state is not None:
        # User has not managed to verify their phone number using this state,
        # remove it and let the user get a new one
        if existing_state.is_throttled(current_app.conf.throttle_resend_seconds):
            raise SMSThrottleException()
        current_app.logger.info('Removing old proofing state')
        current_app.logger.debug(f'Old proofing state: {existing_state.to_dict()}')
        current_app.proofing_statedb.remove_state(existing_state)

    # Create a new proofing state
    verification = PhoneProofingElement(number=phone, verification_code=get_short_hash(), created_by='phone')
    proofing_state = PhoneProofingState(id=None, modified_ts=None, eppn=user.eppn, verification=verification)
    # XXX This should be an atomic transaction together with saving the user and sending the sms.
    current_app.proofing_statedb.save(proofing_state)
    current_app.logger.info('Created phone number verification state')
    current_app.logger.debug(f'Proofing state: {proofing_state.to_dict()}')
    return proofing_state


def send_verification_code(user: User, phone_number: str) -> None:
    """
    Send a SMS with a one-time verification code to the users phone number
    """
    state = get_new_proofing_state(user, phone_number)
    context = {
        'site_name': current_app.conf.eduid_site_name,
        'verification_code': state.verification.verification_code,
    }
    message = render_template('phone_verification_sms.jinja2', **context)

    try:
        current_app.msg_relay.sendsms(phone_number, message, state.reference)
    except MsgTaskFailed as e:
        current_app.logger.error('Phone number verification sms NOT sent')
        current_app.logger.exception(e)
        raise e

    current_app.logger.info('Phone number verification sms sent')
    current_app.logger.debug(f'Phone number: {phone_number}')


def verify_phone_number(state: PhoneProofingState, proofing_user: ProofingUser) -> None:
    """
    :param proofing_user: ProofingUser
    :param state: Phone proofing state

    :return: None

    """
    number = state.verification.number
    phone = proofing_user.phone_numbers.find(number)
    if not phone:
        phone = PhoneNumber(number=number, created_by='eduid_phone', is_verified=True, is_primary=False)
        proofing_user.phone_numbers.add(phone)
        # Adding the phone to the list creates a copy of the element, so we have to 'find' it again
        phone = proofing_user.phone_numbers.find(phone.key)
        assert phone is not None  # ensure mypy

    phone.is_verified = True
    if not proofing_user.phone_numbers.primary:
        phone.is_primary = True

    phone_number_proofing = PhoneNumberProofing(
        eppn=proofing_user.eppn,
        created_by='phone',
        phone_number=state.verification.number,
        reference=state.reference,
        proofing_version='2013v1',
    )
    if current_app.proofing_log.save(phone_number_proofing):
        save_and_sync_user(proofing_user)
        current_app.logger.info('Phone number confirmed')
        current_app.stats.count(name='mobile_verify_success', value=1)
        current_app.logger.info('Removing proofing state')
        current_app.logger.debug(f'Proofing state: {state}')
        current_app.proofing_statedb.remove_state(state)
