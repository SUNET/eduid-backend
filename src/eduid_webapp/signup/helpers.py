# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 NORDUnet A/S
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

import datetime
import os
import struct
import time
from enum import unique

import proquint
from bson import ObjectId
from flask import abort

from eduid_common.api.messages import FluxData, TranslatableMsg, error_response, success_response
from eduid_common.api.utils import save_and_sync_user
from eduid_common.session import session
from eduid_userdb.credentials import Password
from eduid_userdb.exceptions import UserOutOfSync
from eduid_userdb.tou import ToUEvent

from eduid_webapp.signup.app import current_signup_app as current_app
from eduid_webapp.signup.vccs import generate_password


@unique
class SignupMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # the ToU has not been accepted
    no_tou = 'signup.tou-not-accepted'
    # partial success registering new account
    reg_new = 'signup.registering-new'
    # The email address used is already known
    email_used = 'signup.registering-address-used'
    # recaptcha not verified
    no_recaptcha = 'signup.recaptcha-not-verified'
    # verification email successfully re-sent
    resent_success = 'signup.verification-present'
    # unrecognized verfication code
    unknown_code = 'signup.unknown-code'
    # the verification code has already been verified
    already_verified = 'signup.already-verified'


def generate_eppn():
    """
    Generate a unique eduPersonPrincipalName.

    Unique is defined as 'at least it doesn't exist right now'.

    :return: eppn
    :rtype: string or None
    """
    for _ in range(10):
        eppn_int = struct.unpack('I', os.urandom(4))[0]
        eppn = proquint.uint2quint(eppn_int)
        try:
            current_app.central_userdb.get_user_by_eppn(eppn)
        except current_app.central_userdb.exceptions.UserDoesNotExist:
            return eppn
    abort(500)


def check_email_status(email):
    """
    Check the email registration status.

    If the email doesn't exist in database, then return 'new'.
    If exists and it hasn't been verified, then return 'resend-code'.
    If exists and it has been verified before, then return 'address-used'.

    :param email: Address to look for
    :type email: str | unicode

    :return: status
    :rtype: string or None
    """
    userdb = current_app.central_userdb
    signup_db = current_app.private_userdb
    try:
        am_user = userdb.get_user_by_mail(email, raise_on_missing=True, include_unconfirmed=False)
        current_app.logger.debug("Found user {} with email {}".format(am_user, email))
        return 'address-used'
    except userdb.exceptions.UserDoesNotExist:
        current_app.logger.debug("No user found with email {} in central userdb".format(email))
    except userdb.exceptions.UserHasNotCompletedSignup:
        current_app.logger.warning("Incomplete user found with email {} in central userdb".format(email))

    signup_user = signup_db.get_user_by_pending_mail_address(email)
    if signup_user is not None:
        current_app.logger.debug("Found user {} with pending email {} in signup db".format(signup_user, email))
        return 'resend-code'

    current_app.logger.debug("Registering new user with email {}".format(email))
    current_app.stats.count(name='signup_started')
    return 'new'


def remove_users_with_mail_address(email):
    """
    Remove all users with a certain (confirmed) e-mail address from signup_db.

    When syncing of signed up users fail, they remain in the signup_db in a completed state
    (no pending mail address). This prevents the user from signing up again, and they can't
    use their new eduid account either since it is not synced to the central userdb.

    An option would have been to sync the user again, now, but that was deemed more
    surprising to the user so instead we remove all the unsynced users from signup_db
    so the user can do a new signup.

    :param email: E-mail address
    :param email: str | unicode

    :return: None
    """
    signup_db = current_app.private_userdb
    # The e-mail address does not exist in userdb (checked by caller), so if there exists a user
    # in signup_db with this (non-pending) e-mail address, it is probably left-overs from a
    # previous signup where the sync to userdb failed. Clean away all such users in signup_db
    # and continue like this was a completely new signup.
    completed_users = signup_db.get_user_by_mail(email, raise_on_missing=False, return_list=True)
    for user in completed_users:
        current_app.logger.warning('Removing old user {} with e-mail {} from signup_db'.format(user, email))
        signup_db.remove_user_by_id(user.user_id)


def complete_registration(signup_user) -> FluxData:
    """
    After a successful registration:
    * record acceptance of TOU
    * generate a password,
    * add it to the user record,
    * update the attribute manager db with the new account,
    * create authn token for the dashboard,
    * return information to be sent to the user.

    :param signup_user: SignupUser instance
    :type signup_user: SignupUser

    :return: registration status info
    """
    current_app.logger.info("Completing registration for user " "{}".format(signup_user))

    context = {}
    password_id = ObjectId()
    (password, salt) = generate_password(str(password_id), signup_user)

    credential = Password.from_dict(dict(credential_id=password_id, salt=salt, is_generated=True, created_by='signup'))
    signup_user.passwords.add(credential)
    # Record the acceptance of the terms of use
    record_tou(signup_user, 'signup')
    try:
        save_and_sync_user(signup_user)
    except UserOutOfSync:
        current_app.logger.error('Couldnt save user {}, ' 'data out of sync'.format(signup_user))
        return error_response(message='user-out-of-sync')

    timestamp = datetime.datetime.fromtimestamp(int(time.time()))
    if session.common is not None:  # please mypy
        session.common.eppn = signup_user.eppn
    if session.signup is not None:  # please mypy
        session.signup.ts = timestamp
    context.update(
        {
            "status": 'verified',
            "password": password,
            "email": signup_user.mail_addresses.primary.email,
            "dashboard_url": current_app.config.signup_authn_url,
        }
    )

    current_app.stats.count(name='signup_complete')
    current_app.logger.info("Signup process for new user {} complete".format(signup_user))
    return success_response(payload=context)


def record_tou(user, source):
    """
    Record user acceptance of terms of use.

    :param user: the user that has accepted the ToU
    :type user: eduid_userdb.signup.SignupUser
    :param source: An identificator for the proccess during which
                   the user has accepted the ToU (e.g., "signup")
    :type source: str

    :return: None
    """
    event_id = ObjectId()
    created_ts = datetime.datetime.utcnow()
    tou_version = current_app.config.tou_version
    current_app.logger.info(
        'Recording ToU acceptance {!r} (version {})'
        ' for user {} (source: {})'.format(event_id, tou_version, user, source)
    )
    user.tou.add(
        ToUEvent.from_dict(dict(version=tou_version, created_by=source, created_ts=created_ts, event_id=event_id))
    )
