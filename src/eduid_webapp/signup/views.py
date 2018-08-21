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
from flask import render_template
from flask_babel import gettext as _

from eduid_common.api.decorators import MarshalWith, UnmarshalWith
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_webapp.signup.schemas import RegisterEmailSchema
from eduid_webapp.signup.schemas import AccountCreatedResponse
from eduid_webapp.signup.schemas import EmailSchema
from eduid_webapp.signup.verifications import verify_recaptcha
from eduid_webapp.signup.verifications import send_verification_mail
from eduid_webapp.signup.verifications import verify_email_code
from eduid_webapp.signup.helpers import check_email_status
from eduid_webapp.signup.helpers import remove_users_with_mail_address
from eduid_webapp.signup.helpers import complete_registration
from eduid_webapp.signup.verifications import CodeDoesNotExist
from eduid_webapp.signup.verifications import AlreadyVerifiedException

signup_views = Blueprint('signup', __name__, url_prefix='', template_folder='templates')


def _get_tous(version=None):
    if version is None:
        version = current_app.config.get('CURRENT_TOU_VERSION')
    langs = current_app.config.get('AVAILABLE_LANGUAGES').keys()
    tous = {}
    for lang in langs:
        name = 'tous/tou-{}-{}.txt'.format(version, lang)
        tous[lang] = render_template(name)
    return tous


@signup_views.route('/config', methods=['GET'])
@MarshalWith(FluxStandardAction)
def get_config():

    jsconfig = {
            'csrf_token': session.get_csrf_token(),
            'recaptcha_public_key': current_app.config.get('RECAPTCHA_PUBLIC_KEY'),
            'available_languages': current_app.config.get('AVAILABLE_LANGUAGES'),
            'debug': current_app.config.get('DEBUG'),
            'tous': _get_tous(),
            'dashboard_url': current_app.config.get('DASHBOARD_URL'),
            'reset_passwd_url': current_app.config.get('RESET_PASSWD_URL'),
            'students_link': current_app.config.get('STUDENTS_LINK'),
            'technicians_link': current_app.config.get('TECHNICIANS_LINK'),
            'staff_link': current_app.config.get('STAFF_LINK'),
            'faq_link': current_app.config.get('FAQ_LINK'),
            }
    return jsconfig


@signup_views.route('/get-tous', methods=['GET'])
@MarshalWith(FluxStandardAction)
def get_tous():
    """
    View to GET the current TOU in all available languages
    """
    version = request.args.get('version', None)
    return _get_tous(version=version)


@signup_views.route('/trycaptcha', methods=['POST'])
@UnmarshalWith(RegisterEmailSchema)
@MarshalWith(AccountCreatedResponse)
def trycaptcha(email, recaptcha_response, tou_accepted):
    """
    Kantara requires a check for humanness even at level AL1.
    """
    if not tou_accepted:
        return {
                '_status': 'error',
                'message': 'signup.tou-not-accepted'
        }
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
        next = check_email_status(email)
        if next == 'new':
            # Workaround for failed earlier sync of user to userdb: Remove any signup_user with this e-mail address.
            remove_users_with_mail_address(email)
            send_verification_mail(email)
        msg = 'signup.registering-{}'.format(next)
        return {
            'message': msg,
            'next': next
        }
    return {
            '_status': 'error',
            'message': 'signup.recaptcha-not-verified'
    }


@signup_views.route('/resend-verification', methods=['POST'])
@UnmarshalWith(EmailSchema)
@MarshalWith(FluxStandardAction)
def resend_email_verification(email):
    """
    The user has not yet verified the email address.
    Send a verification message to the address so it can be verified.
    """
    current_app.logger.debug("Resend email confirmation to {!s}".format(email))
    send_verification_mail(email)

    return {'message': 'signup.verification-resent'}


@signup_views.route('/verify-link/<code>', methods=['GET'])
@MarshalWith(FluxStandardAction)
def verify_link(code):
    try:
        user = verify_email_code(code)    
    except CodeDoesNotExist:
        return {
                'status': 'unknown-code',
                'message': 'signup.unknown-code'
                }
    except AlreadyVerifiedException:
        return {
                'status': 'already-verified',
                'message': 'signup.already-verified'
                }
    return complete_registration(user)
