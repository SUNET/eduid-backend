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
from flask import redirect

from eduid_common.api.decorators import MarshalWith, UnmarshalWith
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_webapp.email.schemas import VerificationCodeSchema
from eduid_webapp.signup.schemas import RegisterEmailSchema
from eduid_webapp.signup.schemas import EmailSchema
from eduid_webapp.signup.verifications import verify_recaptcha
from eduid_webapp.signup.verifications import send_verification_mail
from eduid_webapp.signup.helpers import check_email_status
from eduid_webapp.signup.helpers import remove_users_with_mail_address
from eduid_webapp.signup.helpers import locale_negotiator
from eduid_webapp.signup.verifications import CodeDoesNotExist
from eduid_webapp.signup.verifications import AlreadyVerifiedException

signup_views = Blueprint('signup', __name__, url_prefix='')


@signup_views.route('/config', methods=['GET'])
@MarshalWith(FluxStandardAction)
def get_config():

    parser = EtcdConfigParser('/eduid/webapp/signup/')
    config = parser.read_configuration(silent=True)
    jsconfig = {
            'csrf_token': session.get_csrf_token(),
            'recaptcha_public_key': config.get('RECAPTCHA_PUBLIC_KEY')
            }
    return jsconfig


@signup_views.route('/trycaptcha', methods=['POST'])
@UnmarshalWith(RegisterEmailSchema)
@MarshalWith(FluxStandardAction)
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
        status = check_email_status(email)
        if status == 'new':
            # Workaround for failed earlier sync of user to userdb: Remove any signup_user with this e-mail address.
            remove_users_with_mail_address(email)
            send_verification_mail(email)
        msg = 'signup.registering-{}'.format(status)
        return {'message': msg}
    return {
            '_status': 'error',
            'message': 'signup.recaptcha-not-verified'
    }


@signup_views.route('/resend-verification', methods=['POST'])
@UnmarshalWith(EmailSchema)
@MarshalWith(FluxStandardAction)
def resend_email_verification(email):
    """
    The user has no yet verified the email address.
    Send a verification message to the address so it can be verified.
    """
    logger.debug("Resend email confirmation to {!s}".format(email))
    send_verification_mail(email)

    return {'message': 'signup.verification-resent'}


@signup_views.route('/verify-code', methods=['POST'])
@UnmarshalWith(VerificationCodeSchema)
@MarshalWith(FluxStandardAction)
def verify_code(code, email):
    try:
        user = verify_email_code(code)    
    except CodeDoesNotExist:
        return {
                '_status': 'error',
                'message': 'signup.unknown-code'
                }
    except AlreadyVerifiedException:
        return {
                '_status': 'error',
                'message': 'signup.already-verified'
                }
    return complete_registration(user)


@signup_views.route('/verify-link/<code>', methods=['GET'])
@MarshalWith(FluxStandardAction)
def verify_link(code):
    try:
        user = verify_email_code(code)    
    except CodeDoesNotExist:
        redirect()
    except AlreadyVerifiedException:
        redirect()
    context = complete_registration(user)
