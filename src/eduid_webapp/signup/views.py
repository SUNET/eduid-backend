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

from flask import Blueprint, abort, request

from eduid_common.api.decorators import MarshalWith, UnmarshalWith
from eduid_common.api.helpers import check_magic_cookie
from eduid_common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_userdb.exceptions import EduIDUserDBError

from eduid_webapp.signup.app import current_signup_app as current_app
from eduid_webapp.signup.helpers import (
    SignupMsg,
    check_email_status,
    complete_registration,
    remove_users_with_mail_address,
)
from eduid_webapp.signup.schemas import AccountCreatedResponse, EmailSchema, RegisterEmailSchema
from eduid_webapp.signup.verifications import (
    AlreadyVerifiedException,
    CodeDoesNotExist,
    ProofingLogFailure,
    send_verification_mail,
    verify_email_code,
    verify_recaptcha,
)

signup_views = Blueprint('signup', __name__, url_prefix='', template_folder='templates')


@signup_views.route('/trycaptcha', methods=['POST'])
@UnmarshalWith(RegisterEmailSchema)
@MarshalWith(AccountCreatedResponse)
def trycaptcha(email, recaptcha_response, tou_accepted):
    """
    Kantara requires a check for humanness even at level AL1.
    """
    if not tou_accepted:
        return error_response(message=SignupMsg.no_tou)

    config = current_app.config
    recaptcha_verified = False

    # add a backdoor to bypass recaptcha checks for humanness,
    # to be used in testing environments for automated integration tests.
    if check_magic_cookie(config):
        current_app.logger.info('Using BACKDOOR to verify reCaptcha during signup!')
        recaptcha_verified = True

    # common path with no backdoor
    if not recaptcha_verified:
        remote_ip = request.remote_addr
        recaptcha_public_key = config.recaptcha_public_key

        if recaptcha_public_key:
            recaptcha_private_key = config.recaptcha_private_key
            recaptcha_verified = verify_recaptcha(recaptcha_private_key, recaptcha_response, remote_ip)
        else:
            recaptcha_verified = False
            current_app.logger.info('Missing configuration for reCaptcha!')

    if recaptcha_verified:
        next = check_email_status(email)
        if next == 'new':
            # Workaround for failed earlier sync of user to userdb: Remove any signup_user with this e-mail address.
            remove_users_with_mail_address(email)
            send_verification_mail(email)
            return success_response(payload=dict(next=next), message=SignupMsg.reg_new)

        elif next == 'resend-code':
            return {'next': next}

        elif next == 'address-used':
            current_app.stats.count(name='address_used_error')
            return error_response(payload=dict(next=next), message=SignupMsg.email_used)

    return error_response(message=SignupMsg.no_recaptcha)


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
    return success_response(message=SignupMsg.resent_success)


@signup_views.route('/verify-link/<code>', methods=['GET'])
@MarshalWith(FluxStandardAction)
def verify_link(code: str) -> FluxData:
    try:
        user = verify_email_code(code)
    except CodeDoesNotExist:
        return error_response(payload=dict(status='unknown-code'), message=SignupMsg.unknown_code)

    except AlreadyVerifiedException:
        return error_response(payload=dict(status='already-verified'), message=SignupMsg.already_verified)

    except ProofingLogFailure:
        return error_response(message=CommonMsg.temp_problem)

    except EduIDUserDBError:
        return error_response(payload=dict(status='unknown-code'), message=SignupMsg.unknown_code)

    return complete_registration(user)


@signup_views.route('/get-code', methods=['GET'])
def get_email_code():
    """
    Backdoor to get the email verification code in the staging or dev environments
    """
    try:
        if check_magic_cookie(current_app.config):
            email = request.args.get('email')
            signup_user = current_app.private_userdb.get_user_by_pending_mail_address(email)
            code = signup_user.pending_mail_address.verification_code
            return code
    except Exception:
        current_app.logger.exception("Someone tried to use the backdoor to get the email verification code for signup")

    abort(400)
