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

import os
import time
import struct
import datetime
from hashlib import sha256
from bson import ObjectId
import proquint

from flask import current_app, request, abort

from eduid_common.api.utils import save_and_sync_user
from eduid_userdb.exceptions import UserOutOfSync
from eduid_userdb.password import Password
from eduid_userdb.tou import ToUEvent
from eduid_webapp.signup.vccs import generate_password


def locale_negotiator():
    available_languages = current_app.config['AVAILABLE_LANGUAGES'].keys()
    cookie_name = current_app.config['LANG_COOKIE_NAME']

    cookie_lang = request.cookies.get(cookie_name, None)
    if cookie_lang and cookie_lang in available_languages:
        return cookie_lang

    locale_name = request.accept_language.best_match(available_languages)

    if locale_name not in available_languages:
        locale_name = current_app.config.get('DEFAULT_LOCALE_NAME', 'sv')
    return locale_name


def generate_eppn():
    """
    Generate a unique eduPersonPrincipalName.

    Unique is defined as 'at least it doesn't exist right now'.

    :param request:
    :return: eppn
    :rtype: string
    """
    for _ in range(10):
        eppn_int = struct.unpack('I', os.urandom(4))[0]
        eppn = proquint.from_int(eppn_int)
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
    """
    userdb = current_app.central_userdb
    signup_db = current_app.private_userdb
    try:
        am_user = userdb.get_user_by_mail(email, raise_on_missing=True, include_unconfirmed=False)
        current_app.logger.debug("Found user {!s} with email {!s}".format(am_user, email))
        return 'address-used'
    except userdb.exceptions.UserDoesNotExist:
        current_app.logger.debug("No user found with email {!s} in eduid userdb".format(email))

    try:
        signup_user = signup_db.get_user_by_pending_mail_address(email)
        if signup_user:
            current_app.logger.debug("Found user {!s} with pending email {!s} in signup db".format(signup_user, email))
            return 'resend-code'
    except userdb.exceptions.UserDoesNotExist:
        current_app.logger.debug("No user found with email {!s} in signup db either".format(email))

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

    :return:
    """
    signup_db = current_app.private_userdb
    # The e-mail address does not exist in userdb (checked by caller), so if there exists a user
    # in signup_db with this (non-pending) e-mail address, it is probably left-overs from a
    # previous signup where the sync to userdb failed. Clean away all such users in signup_db
    # and continue like this was a completely new signup.
    completed_users = signup_db.get_user_by_mail(email, raise_on_missing = False, return_list = True)
    for user in completed_users:
        current_app.logger.warning('Removing old user {!s} with e-mail {!s} from signup_db'.format(user, email))
        signup_db.remove_user_by_id(user.user_id)


def complete_registration(signup_user, context=None):
    """
    After a successful registration
    generate a password,
    add it to the registration record in the registrations db,
    update the attribute manager db with the new account,
    and send the pertinent information to the user.

    :param signup_user: SignupUser instance
    :type signup_user: SignupUser
    """
    current_app.logger.info("Completing registration for user "
                    "{}".format(signup_user))

    if context is None:
        context = {}
    password_id = ObjectId()
    (password, salt) = generate_password(str(password_id), signup_user)

    credential = Password(credential_id=password_id, salt=salt, application='signup')
    signup_user.passwords.add(credential)
    # Record the acceptance of the terms of use
    record_tou(signup_user, 'signup')
    try:
        save_and_sync_user(signup_user)
    except UserOutOfSync:
        current_app.logger.debug('Couldnt save user {}, '
                                 'data out of sync'.format(signup_user))
        return {
            '_status': 'error',
            'message': 'user-out-of-sync'
        }

    secret = current_app.config.get('AUTH_SHARED_SECRET')
    timestamp = '{:x}'.format(int(time.time()))
    nonce = os.urandom(16).encode('hex')
    auth_token = generate_auth_token(secret, signup_user.eppn, nonce, timestamp)

    context.update({
        "status": 'verified',
        "password": password,
        "email": signup_user.mail_addresses.primary.email,
        "eppn": signup_user.eppn,
        "nonce": nonce,
        "timestamp": timestamp,
        "auth_token": auth_token,
        "dashboard_url": current_app.config.get('AUTH_TOKEN_URL')
    })

    current_app.logger.info("Signup process for new user {} complete".format(signup_user))
    return context


def record_tou(user, source):
    """
    Record user acceptance of terms of use.

    :param user: the user that has accepted the ToU
    :type user: eduid_userdb.signup.User
    :param source: An identificator for the proccess during which
                   the user has accepted the ToU (e.g., "signup")
    :type source: str
    """
    event_id = ObjectId()
    created_ts = datetime.datetime.utcnow()
    tou_version = current_app.config['TOU_VERSION']
    current_app.logger.debug('Recording ToU acceptance {!r} (version {!s})'
                 ' for user {!r} (source: {!s})'.format(
                     event_id, tou_version,
                     user.user_id, source))
    user.tou.add(ToUEvent(
        version = tou_version,
        application = source,
        created_ts = created_ts,
        event_id = event_id
        ))


def generate_auth_token(shared_key, email, nonce, timestamp, generator=sha256):
    """
        The shared_key is a secret between the two systems
        The public word must must go through form POST or GET
    """
    current_app.logger.debug("Generating auth-token for user {!r}, "
                        "nonce {!r}, ts {!r}".format(email, nonce, timestamp))
    return generator("{0}|{1}|{2}|{3}".format(
        shared_key, email, nonce, timestamp)).hexdigest()
