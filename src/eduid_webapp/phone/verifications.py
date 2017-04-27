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

from flask import current_app

from eduid_common.api.utils import get_unique_hash
from eduid_userdb.proofing import PhoneProofingElement, PhoneProofingState


def new_verification_code(phone, user):
    old_verification = current_app.verifications_db.get_state_by_eppn_and_mobile(
                       user.eppn, phone, raise_on_missing=False)
    if old_verification is not None:
        current_app.logger.debug('removing old verification code:'
                                 ' {!r}.'.format(old_verification.to_dict()))
        current_app.verifications_db.remove_state(old_verification)

    code = get_unique_hash()
    verification = PhoneProofingElement(phone=phone,
                                        verification_code=code,
                                        application='dashboard')
    verification_data = {
        'eduPersonPrincipalName': user.eppn,
        'verification': verification.to_dict()
        }
    verification_state = PhoneProofingState(verification_data)
    # XXX This should be an atomic transaction together with saving
    # the user and sending the letter.
    current_app.verifications_db.save(verification_state)
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
