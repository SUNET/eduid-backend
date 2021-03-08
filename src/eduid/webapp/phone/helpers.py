#
# Copyright (c) 2020 SUNET
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
#     3. Neither the name of the SUNET nor the names of its
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

from enum import unique

from eduid_common.api.messages import TranslatableMsg


@unique
class PhoneMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # validation error: not conforming to e164
    e164_error = "phone.e164_format"
    # validation error: invalid phone number
    phone_invalid = "phone.phone_format"
    # validation error: invalid swedish number
    swedish_invalid = "phone.swedish_mobile_format"
    # validation error: duplicated phone
    dupe = "phone.phone_duplicated"
    # successfully saved phone number
    save_success = 'phones.save-success'
    # cannot set unconfirmed phone number as primary
    unconfirmed_primary = 'phones.unconfirmed_number_not_primary'
    # successfully set phone number as primary number
    primary_success = 'phones.primary-success'
    # The received verification code is invalid or has expired
    code_invalid = 'phones.code_invalid_or_expired'
    # the received phone to be set as primary is unknown
    unknown_phone = 'phones.unknown_phone'
    # success verifying phone number
    verify_success = 'phones.verification-success'
    # success removing phone number
    removal_success = 'phones.removal-success'
    # the previously sent verification code is still valid
    still_valid_code = 'still-valid-code'
    # success re-sending a verification code
    resend_success = 'phones.code-sent'
