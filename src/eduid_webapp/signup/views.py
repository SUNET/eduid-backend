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

import requests
from flask import Blueprint, request, abort, render_template

from eduid_common.api.decorators import MarshalWith, UnmarshalWith
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_common.session import session
from eduid_webapp.signup.helpers import check_email_status, remove_users_with_mail_address, complete_registration
from eduid_webapp.signup.schemas import RegisterEmailSchema, AccountCreatedResponse, EmailSchema
from eduid_webapp.signup.verifications import CodeDoesNotExist, AlreadyVerifiedException, ProofingLogFailure
from eduid_webapp.signup.verifications import verify_recaptcha, send_verification_mail, verify_email_code
from eduid_webapp.signup.app import current_signup_app as current_app

signup_views = Blueprint('signup', __name__, url_prefix='', template_folder='templates')


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
    recaptcha_public_key = config.recaptcha_public_key

    if recaptcha_public_key:
        recaptcha_private_key = config.recaptcha_private_key
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
            current_app.stats.count(name='address_used_error')
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
    current_app.stats.count(name='resend_code')
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
