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
class EmailMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # the requested email is missing
    missing = 'emails.missing'
    # the provided email is duplicated
    dupe = 'emails.duplicated'
    # success retrieving the account's emails
    get_success = 'emails.get-success'
    # A verification mail for that address has been sent recently
    throttled = 'emails.throttled'
    still_valid_code = 'still-valid-code'
    # The email has been added, but no verification code has been sent (throttled)
    added_and_throttled = 'emails.added-and-throttled'
    # succesfully saved new email address
    saved = 'emails.save-success'
    # trying to set as primary an unconfirmed address
    unconfirmed_not_primary = 'emails.unconfirmed_address_not_primary'
    # success setting email address as primary
    success_primary = 'emails.primary-success'
    # the received verification code was invalid or expired
    invalid_code = 'emails.code_invalid_or_expired'
    # unknown email received to set as primary
    unknown_email = 'emails.unknown_email'
    # success verifying email
    verify_success = 'emails.verification-success'
    # it's not allowed to remove all email addresses
    cannot_remove_last = 'emails.cannot_remove_unique'
    # it's not allowed to remove all verified email addresses
    cannot_remove_last_verified = 'emails.cannot_remove_unique_verified'
    # success removing an email address
    removal_success = 'emails.removal-success'
    # success sending a verification code
    code_sent = 'emails.code-sent'
