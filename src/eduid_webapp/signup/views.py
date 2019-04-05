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

import requests
from flask import Blueprint, request, current_app, abort

from eduid_common.session import session
from eduid_common.api.decorators import MarshalWith, UnmarshalWith
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_webapp.signup.schemas import RegisterEmailSchema, AccountCreatedResponse, EmailSchema
from eduid_webapp.signup.verifications import verify_recaptcha, send_verification_mail, verify_email_code
from eduid_webapp.signup.helpers import check_email_status, remove_users_with_mail_address, complete_registration
from eduid_webapp.signup.verifications import CodeDoesNotExist, AlreadyVerifiedException, ProofingLogFailure


signup_views = Blueprint('signup', __name__, url_prefix='', template_folder='templates')


@signup_views.route('/config', methods=['GET'])
@MarshalWith(FluxStandardAction)
def get_config():
    tou_url = current_app.config.get('TOU_URL')
    try:
        r = requests.get(tou_url, verify=False)
        current_app.logger.debug('Response: {!r} with headers: {!r}'.format(r, r.headers))
        if r.status_code == 302:
            headers = {'Cookie': r.headers.get('Set-Cookie')}
            current_app.logger.debug('Headers: {!r}'.format(headers))
            r = requests.get(tou_url, headers=headers, verify=False)
            current_app.logger.debug('2nd response: {!r} with headers: {!r}'.format(r, r.headers))
    except requests.exceptions.HTTPError as e:
        current_app.logger.error('Problem getting tous from URL {!r}: {!r}'.format(tou_url, e))
        abort(500)
    if r.status_code != 200:
        current_app.logger.debug('Problem getting config, '
                                 'response status: '
                                 '{!r}'.format(r.status_code))
        abort(500)
    return {
            'csrf_token': session.get_csrf_token(),
            'recaptcha_public_key': current_app.config.get('RECAPTCHA_PUBLIC_KEY'),
            'available_languages': current_app.config.get('AVAILABLE_LANGUAGES'),
            'debug': current_app.config.get('DEBUG'),
            'tous': r.json()['payload'],
            'dashboard_url': current_app.config.get('DASHBOARD_URL'),
            'reset_passwd_url': current_app.config.get('RESET_PASSWD_URL'),
            'students_link': current_app.config.get('STUDENTS_LINK'),
            'technicians_link': current_app.config.get('TECHNICIANS_LINK'),
            'staff_link': current_app.config.get('STAFF_LINK'),
            'faq_link': current_app.config.get('FAQ_LINK'),
            }


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
            return {
                'message': 'signup.registering-new',
                'next': next
            }
        elif next == 'resend-code':
            return {
                'next': next
            }
        elif next == 'address-used':
            return {
                '_status': 'error',
                'message': 'signup.registering-address-used',
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
                '_status': 'error',
                'status': 'unknown-code',
                'message': 'signup.unknown-code'
                }
    except AlreadyVerifiedException:
        return {
                '_status': 'error',
                'status': 'already-verified',
                'message': 'signup.already-verified'
                }
    except ProofingLogFailure:
        return {
            '_status': 'error',
            'message': 'Temporary technical problems'
        }
    return complete_registration(user)
