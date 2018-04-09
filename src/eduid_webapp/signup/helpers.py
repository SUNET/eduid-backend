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
from uuid import uuid4
import struct
import proquint
import time
import requests

from flask import current_app, abort

from eduid_userdb.signup import SignupUser
from eduid_userdb.proofing import EmailProofingElement


def verify_recaptcha(secret_key, captcha_response, user_ip, retries=3):
    """
    :param secret_key: Recaptcha secret key
    :param captcha_response: User recaptcha response
    :param user_ip: User ip address
    :param retries: Number of times to retry sending recaptcha response

    :type secret_key: str
    :type captcha_response: str
    :type user_ip: str
    :type retries: int

    :return: True|False
    :rtype: bool
    """
    url = 'https://www.google.com/recaptcha/api/siteverify'
    params = {
        'secret': secret_key,
        'response': captcha_response,
        'remoteip': user_ip
    }
    while retries:
        retries -= 1
        try:
            current_app.logger.debug('Sending the CAPTCHA response')
            verify_rs = requests.get(url, params=params, verify=True)
            current_app.logger.debug("CAPTCHA response: {}".format(verify_rs))
            verify_rs = verify_rs.json()
            if verify_rs.get('success', False) is True:
                return True
        except requests.exceptions.RequestException as e:
            if not retries:
                current_app.logger.error('Caught RequestException while '
                                         'sending CAPTCHA, giving up.')
                raise e
            current_app.logger.warning('Caught RequestException while '
                                       'sending CAPTCHA, trying again.')
            current_app.logger.warning(e)
            time.sleep(0.5)

    current_app.logger.info("Invalid CAPTCHA response from {}: {}".format(
        user_ip, verify_rs.get('error-codes', 'Unspecified error')))
    return False


def generate_verification_link():
    code = text_type(uuid4())
    # XXX link = request.route_url("email_verification_link", code=code)
    return (link, code)


def generate_eppn(request):
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


def send_verification_mail(request, email):
    mailer = get_mailer(request)
    (verification_link, code) = generate_verification_link(request)

    context = {
        "email": email,
        "verification_link": verification_link,
        "site_url": request.route_url("home"),
        "site_name": request.registry.settings.get("site.name", "eduid_signup"),
        # We stopped sending the code to avoid confusing our users
        #"code": code,
        "verification_code_form_link": request.route_url("verification_code_form"),
    }

    message = Message(
        subject=_("eduid-signup verification email"),
        sender=request.registry.settings.get("mail.default_sender"),
        recipients=[email],
        body=render(
            "templates/verification_email.txt.jinja2",
            context,
            request,
        ),
        html=render(
            "templates/verification_email.html.jinja2",
            context,
            request,
        ),
    )

    signup_user = request.signup_db.get_user_by_pending_mail_address(email)
    if not signup_user:
        mailaddress = EmailProofingElement(email = email, application = 'signup', verified = False,
                                           verification_code = code)
        signup_user = SignupUser(eppn = generate_eppn(request))
        signup_user.pending_mail_address = mailaddress
        request.signup_db.save(signup_user)
        logger.info("New user {!s}/{!s} created. e-mail is pending confirmation.".format(signup_user, email))
    else:
        # update mailaddress on existing user with new code
        signup_user.pending_mail_address.verification_code = code
        request.signup_db.save(signup_user)
        logger.info("User {!s}/{!s} updated with new e-mail confirmation code".format(signup_user, email))

    if request.registry.settings.get("development", '') != 'true':
        mailer.send(message)
    else:
        # Development
        logger.debug("Confirmation e-mail:\nFrom: {!s}\nTo: {!s}\nSubject: {!s}\n\n{!s}".format(
            message.sender, message.recipients, message.subject, message.body))
