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

import time
from uuid import uuid4

import requests
from flask import render_template
from flask_babel import gettext as _

from eduid_common.session import session
from eduid_userdb import MailAddress
from eduid_userdb.logs import MailAddressProofing
from eduid_userdb.proofing import EmailProofingElement
from eduid_userdb.signup import SignupUser

from eduid_webapp.signup.app import current_signup_app as current_app
from eduid_webapp.signup.helpers import generate_eppn


def verify_recaptcha(secret_key, captcha_response, user_ip, retries=3):
    """
    Verify the recaptcha response received from the client
    against the recaptcha API.

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
    params = {'secret': secret_key, 'response': captcha_response, 'remoteip': user_ip}
    while retries:
        retries -= 1
        try:
            current_app.logger.debug('Sending the CAPTCHA response')
            verify_rs = requests.get(url, params=params, verify=True)
            current_app.logger.debug("CAPTCHA response: {}".format(verify_rs))
            verify_rs = verify_rs.json()
            if verify_rs.get('success', False) is True:
                current_app.logger.info("Valid CAPTCHA response from " "{}".format(user_ip))
                return True
        except requests.exceptions.RequestException as e:
            if not retries:
                current_app.logger.error('Caught RequestException while ' 'sending CAPTCHA, giving up.')
                raise e
            current_app.logger.warning('Caught RequestException while ' 'sending CAPTCHA, trying again.')
            current_app.logger.warning(e)
            time.sleep(0.5)

    current_app.logger.info(
        "Invalid CAPTCHA response from {}: {}".format(user_ip, verify_rs.get('error-codes', 'Unspecified error'))
    )
    return False


def generate_verification_link():
    """
    Generate a verification code and build a verification link with it.

    :return: code and link
    :rtype: pair of str
    """
    code = str(uuid4())
    link = '{}code/{}'.format(current_app.config.signup_url, code)
    return link, code


def send_verification_mail(email):
    """
    Render and send an email with a verification code/link
    for the provided email.

    :param email: Email address to verify
    :type email: str | unicode
    """
    verification_link, code = generate_verification_link()

    signup_user = current_app.private_userdb.get_user_by_pending_mail_address(email)
    if not signup_user:
        mailaddress = EmailProofingElement.from_dict(
            dict(email=email, created_by='signup', verified=False, verification_code=code)
        )
        signup_user = SignupUser.from_dict(data=dict(eduPersonPrincipalName=generate_eppn()))
        signup_user.pending_mail_address = mailaddress
        current_app.logger.info("New user {}/{} created. e-mail is pending confirmation".format(signup_user, email))
    else:
        # update mailaddress on existing user with new code
        signup_user.pending_mail_address.verification_code = code
        current_app.logger.info("User {}/{} updated with new e-mail confirmation code".format(signup_user, email))

    # Send verification mail
    subject = _("eduid-signup verification email")

    context = {
        "email": email,
        "verification_link": verification_link,
        "site_name": current_app.config.eduid_site_name,
        "site_url": current_app.config.eduid_site_url,
    }

    text = render_template("verification_email.txt.jinja2", **context)
    html = render_template("verification_email.html.jinja2", **context)

    current_app.mail_relay.sendmail(subject, [email], text, html, reference=signup_user.proofing_reference)
    current_app.logger.info("Sent email address verification mail for user {} to address {}".format(signup_user, email))
    current_app.stats.count(name='mail_sent')
    current_app.private_userdb.save(signup_user)
    current_app.logger.info("Saved user {} to private db".format(signup_user))


class AlreadyVerifiedException(Exception):
    pass


class CodeDoesNotExist(Exception):
    pass


class ProofingLogFailure(Exception):
    pass


def verify_email_code(code):
    """
    Look up a user in the signup userdb using an e-mail verification code.

    Mark the e-mail address as confirmed, save the user and return the user object.

    :param code: Code as received from user
    :type code: str | unicode

    :return: Signup user object
    :rtype: SignupUser
    """
    current_app.logger.info("Trying to verify code {}".format(code))

    signup_db = current_app.private_userdb
    signup_user = signup_db.get_user_by_mail_verification_code(code)

    if not signup_user:
        current_app.logger.debug("Code {} not found in database".format(code))
        raise CodeDoesNotExist()

    email = signup_user.pending_mail_address.email
    user = current_app.central_userdb.get_user_by_mail(email, raise_on_missing=False)

    if user:
        current_app.logger.debug("Email {} already present in central db".format(email))
        raise AlreadyVerifiedException()

    mail_dict = signup_user.pending_mail_address.to_dict()
    mail_address = MailAddress.from_dict(mail_dict, raise_on_unknown=False)
    if mail_address.is_verified:
        # There really should be no way to get here, is_verified is set to False when
        # the EmailProofingElement is created.
        current_app.logger.debug("Code {} already verified ({})".format(code, mail_address))
        raise AlreadyVerifiedException()

    mail_address_proofing = MailAddressProofing(
        signup_user,
        created_by='signup',
        mail_address=mail_address.email,
        reference=signup_user.proofing_reference,
        proofing_version='2013v1',
    )
    if current_app.proofing_log.save(mail_address_proofing):
        mail_address.is_verified = True
        mail_address.verified_ts = True
        mail_address.verified_by = 'signup'
        mail_address.is_primary = True
        signup_user.pending_mail_address = None
        signup_user.mail_addresses.add(mail_address)
        result = signup_db.save(signup_user)
        current_app.logger.info("Code {} verified and user {} saved: {!r}".format(code, signup_user, result))
        current_app.stats.count(name='mail_verified')
        return signup_user
    else:
        current_app.logger.error('Failed to save proofing log, aborting')
        raise ProofingLogFailure()
