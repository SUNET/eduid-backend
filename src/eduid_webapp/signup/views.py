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
from eduid_webapp.email.schemas import VerificationCodeSchema
from eduid_webapp.signup.schemas import RegisterEmailSchema
from eduid_webapp.signup.verifications import verify_recaptcha
from eduid_webapp.signup.helpers import get_url_from_email_status
from eduid_webapp.signup.helpers import locale_negotiator

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
        return get_url_from_email_status(request, email)
    return {
        'error': True,
        'recaptcha_public_key': recaptcha_public_key,
        'lang': locale_negotiator(request)
    }

@signup_views.route('/verify-link', methods=['GET'])
@UnmarshalWith(VerificationCodeSchema)
def verify_link(code, email):
    pass
