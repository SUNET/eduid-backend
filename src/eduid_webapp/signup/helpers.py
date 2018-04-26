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
import struct
import proquint

from flask import current_app, request, abort


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


def get_url_from_email_status(email, status):
    """
    Return a view depending on the verification status of the provided email.

    If a user with this (verified) e-mail address exist in the central eduid userdb,
    return view 'email_already_registered'.

    Otherwise, send a verification e-mail.

    :param request: the request
    :type request: WebOb Request
    :param email: the email
    :type email: string

    :return: redirect response
    """
    logger.debug("e-mail {!s} status: {!s}".format(email, status))
    if status == 'new':
        namedview = 'success'
    elif status == 'not_verified':
        request.session['email'] = email
        namedview = 'resend_email_verification'
    elif status == 'verified':
        request.session['email'] = email
        namedview = 'email_already_registered'
    else:
        raise NotImplementedError('Unknown e-mail status: {!r}'.format(status))
    return request.route_url(namedview)


def check_email_status(email):
    """
    Check the email registration status.

    If the email doesn't exist in database, then return 'new'.

    If exists and it hasn't been verified, then return 'not_verified'.

    If exists and it has been verified before, then return 'verified'.

    :param userdb: eduID central userdb
    :param signup_db: Signup userdb
    :param email: Address to look for

    :type userdb: eduid_userdb.UserDb
    :type signup_db: eduid_userdb.signup.SignupUserDB
    :type email: str | unicode
    """
    userdb = current_app.central_userdb
    signup_db = current_app.private_userdb
    try:
        am_user = userdb.get_user_by_mail(email, raise_on_missing=True, include_unconfirmed=False)
        current_app.logger.debug("Found user {!s} with email {!s}".format(am_user, email))
        return 'verified'
    except userdb.exceptions.UserDoesNotExist:
        current_app.logger.debug("No user found with email {!s} in eduid userdb".format(email))

    try:
        signup_user = signup_db.get_user_by_pending_mail_address(email)
        if signup_user:
            current_app.logger.debug("Found user {!s} with pending email {!s} in signup db".format(signup_user, email))
            return 'not_verified'
    except userdb.exceptions.UserDoesNotExist:
        current_app.logger.debug("No user found with email {!s} in signup db either".format(email))

    # Workaround for failed earlier sync of user to userdb: Remove any signup_user with this e-mail address.
    remove_users_with_mail_address(email)

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

    :param signup_db: SignupUserDB
    :param email: E-mail address

    :param signup_db: eduid_userdb.signup.SignupUserDB
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
