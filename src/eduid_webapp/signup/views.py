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

from flask import Blueprint, request, session, current_app

from eduid_common.api.decorators import MarshalWith, UnmarshalWith
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_webapp.signup.schemas import RegisterEmailSchema
from eduid_webapp.signup.helpers import verify_recaptcha

signup_views = Blueprint('signup', __name__, url_prefix='')


@signup_views.route('/register', methods=['POST'])
@UnmarshalWith(RegisterEmailSchema)
@MarshalWith(FluxStandardAction)
def register_email(email):
    current_app.logger.info('Start registration of email {!r}'.format(email))
    session['registering_email'] = email
    current_app.stats.count(name='email_start_registration', value=1)
    return {
            'message': 'register.start-success'
            }

@signup_views.route('/trycaptcha', methods=['POST'])
@UnmarshalWith(RegisterEmailSchema)
def trycaptcha(email, recaptcha_response):
    """
    Kantara requires a check for humanness even at level AL1.
    """
    config = current_app.config
    remote_ip = request.remote_addr
    recaptcha_public_key = config.get('RECAPTCHA_PUBLIC_KEY', '')
        
    if recaptcha_public_key:
        recaptcha_private_key = config.get('RECAPTCHA_PRIVATE_KEY', '')
        recaptcha_verified = verify_recaptcha(recaptcha_private_key,
                                              recaptcha_response, remote_ip)
    else:
        # If recaptcha_public_key is not set recaptcha is disabled
        recaptcha_verified = True
        current_app.logger.info('CAPTCHA disabled')

    if recaptcha_verified:
        current_app.logger.info('Valid CAPTCHA response from {!r}'.format(remote_ip))
        email = session['email']
        return get_url_from_email_status(request, email)
    return {
        'error': True,
        'recaptcha_public_key': recaptcha_public_key,
        'lang': locale_negotiator(request)
    }

def get_url_from_email_status(request, email):
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
    status = check_email_status(request.userdb, request.signup_db, email)
    logger.debug("e-mail {!s} status: {!s}".format(email, status))
    if status == 'new':
        send_verification_mail(request, email)
        namedview = 'success'
    elif status == 'not_verified':
        request.session['email'] = email
        namedview = 'resend_email_verification'
    elif status == 'verified':
        request.session['email'] = email
        namedview = 'email_already_registered'
    else:
        raise NotImplementedError('Unknown e-mail status: {!r}'.format(status))
    url = request.route_url(namedview)

    return HTTPFound(location=url)

def check_email_status(userdb, signup_db, email):
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
    try:
        am_user = userdb.get_user_by_mail(email, raise_on_missing=True, include_unconfirmed=False)
        logger.debug("Found user {!s} with email {!s}".format(am_user, email))
        return 'verified'
    except userdb.exceptions.UserDoesNotExist:
        logger.debug("No user found with email {!s} in eduid userdb".format(email))

    try:
        signup_user = signup_db.get_user_by_pending_mail_address(email)
        if signup_user:
            logger.debug("Found user {!s} with pending email {!s} in signup db".format(signup_user, email))
            return 'not_verified'
    except userdb.exceptions.UserDoesNotExist:
        logger.debug("No user found with email {!s} in signup db either".format(email))

    # Workaround for failed earlier sync of user to userdb: Remove any signup_user with this e-mail address.
    remove_users_with_mail_address(signup_db, email)

    return 'new'
