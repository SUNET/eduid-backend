# -*- coding: utf-8 -*-
#
# Copyright (c) 2019 SUNET
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
from base64 import b64encode
from flask import Blueprint, render_template
from flask import request
from flask_babel import gettext as _

from eduid_common.api.exceptions import MailTaskFailed, MsgTaskFailed
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_common.api.decorators import require_user, MarshalWith, UnmarshalWith
from eduid_common.session import session
from eduid_userdb.security.state import PasswordResetState
from eduid_userdb.security.state import PasswordResetEmailState, PasswordResetEmailAndPhoneState
from eduid_userdb.exceptions import DocumentDoesNotExist
from eduid_webapp.reset_password.schemas import ResetPasswordInitSchema
from eduid_webapp.reset_password.schemas import ResetPasswordEmailCodeSchema
from eduid_webapp.reset_password.schemas import ResetPasswordWithCodeSchema
from eduid_webapp.reset_password.schemas import ResetPasswordWithPhoneCodeSchema
from eduid_webapp.reset_password.schemas import ResetPasswordExtraSecSchema
from eduid_webapp.reset_password.helpers import error_message, success_message
from eduid_webapp.reset_password.helpers import send_password_reset_mail
from eduid_webapp.reset_password.helpers import get_pwreset_state, BadCode, hash_password
from eduid_webapp.reset_password.helpers import generate_suggested_password, reset_user_password
from eduid_webapp.reset_password.helpers import get_extra_security_alternatives, mask_alternatives
from eduid_webapp.reset_password.helpers import verify_email_address
from eduid_webapp.reset_password.helpers import send_verify_phone_code
from eduid_webapp.reset_password.app import current_reset_password_app as current_app


reset_password_views = Blueprint('reset_password', __name__, url_prefix='', template_folder='templates')


@reset_password_views.route('/', methods=['POST'])
@UnmarshalWith(ResetPasswordInitSchema)
@MarshalWith(FluxStandardAction)
def init_reset_pw(email: str) -> dict:
    """
    View that receives an email address and sends an email with a password
    reset link to that address.

    This link will load a (signup/dashboard)? app that will fetch
    a generated password and settings related to that - min entropy, length of
    passwords.

    It returns a message informing of the result of the operation.
    """
    current_app.logger.info(f'Trying to send password reset email to {email}')
    try:
        send_password_reset_mail(email)
    except MailTaskFailed as error:
        current_app.logger.error(f'Sending password reset e-mail for {email} failed: {error}')
        return error_message('resetpw.send-pw-fail')

    return success_message('resetpw.send-pw-success')


@reset_password_views.route('/config', methods=['POST'])
@UnmarshalWith(ResetPasswordEmailCodeSchema)
@MarshalWith(FluxStandardAction)
def config_reset_pw(code: str) -> dict:
    """
    View that receives an emailed code and returns the configuration needed for
    the reset password form.
    """
    current_app.logger.info(f'Configuring password reset frm for {code}')
    try:
        state = get_pwreset_state(code)
    except BadCode as e:
        return error_message(e.msg)

    verify_email_address(state)

    new_password = generate_suggested_password()
    hashed = b64encode(hash_password(new_password)).decode('utf8')
    session.reset_password.generated_password_hash = hashed

    user = current_app.central_userdb.get_user_by_eppn(state.eppn)
    verified_phones = user.phone_numbers.verified.to_list()

    try:
        alternatives = get_extra_security_alternatives(state.eppn)
        state.extra_security = alternatives
        current_app.password_reset_state_db.save(state)
    except DocumentDoesNotExist:
        current_app.logger.error(f'User {state.eppn} not found')
        return error_message('resetpw.user-not-found')

    return {
            'csrf_token': session.get_csrf_token(),
            'suggested_password': new_password,
            'email_code': state.email_code.code,
            'extra_security': mask_alternatives(alternatives),
            }


@reset_password_views.route('/new-pw/', methods=['POST'])
@UnmarshalWith(ResetPasswordWithCodeSchema)
@MarshalWith(FluxStandardAction)
def set_new_pw(code: str, password: str) -> dict:
    try:
        state = get_pwreset_state(code)
    except BadCode as e:
        return error_message(e.msg)

    hashed = b64encode(hash_password(password)).decode('utf8')
    if hashed == session.reset_password.generated_password_hash:
        current_app.logger.info('Generated password used')
        current_app.stats.count(name='reset_password_generated_password_used')
    else:
        current_app.logger.info('Custom password used')
        current_app.stats.count(name='reset_password_custom_password_used')

    current_app.logger.info(f'Resetting password for user {state.eppn}')
    reset_user_password(state, password)
    current_app.logger.info(f'Password reset done, removing state for user {state.eppn}')
    current_app.password_reset_state_db.remove_state(state)
    return success_message('resetpw.pw-resetted')


@reset_password_views.route('/extra-security/', methods=['POST'])
@UnmarshalWith(ResetPasswordExtraSecSchema)
@MarshalWith(FluxStandardAction)
def choose_extra_security(code: str, phone_index: str) -> dict:
    try:
        state = get_pwreset_state(code)
    except BadCode as e:
        return error_message(e.msg)

    current_app.logger.info(f'Password reset: choose_extra_security for {state.eppn}')

    # Check that the email code has been validated
    if not state.email_code.is_verified:
        current_app.logger.info(f'User {state.eppn} has not verified their email address')
        return error_message('resetpw.email-not-validated')

    phone_number = state.extra_security['phone_numbers'][int(phone_index)]
    current_app.logger.info(f'Trying to send password reset sms to user {state.eppn}')
    try:
        send_verify_phone_code(state, phone_number)
    except MsgTaskFailed as e:
        current_app.logger.error(f'Sending sms failed: {e}')
        return error_message('resetpw.sms-failed')

    current_app.stats.count(name='reset_password_extra_security_phone')
    return success_message('resetpw.sms-success')


@reset_password_views.route('/new-pw/', methods=['POST'])
@UnmarshalWith(ResetPasswordWithPhoneCodeSchema)
@MarshalWith(FluxStandardAction)
def set_new_pw_extra_security(phone_code: str, code: str,
                              password: str) -> dict:
    try:
        state = get_pwreset_state(code)
    except BadCode as e:
        return error_message(e.msg)

    if phone_code == state.phone_code.code:
        if not verify_phone_number(state):
            current_app.logger.info(f'Could not verify phone code for {state.eppn}')
            return error_message('resetpw.phone-invalid')

        current_app.logger.info(f'Phone code verified for user {state.eppn}')
        current_app.stats.count(name='reset_password_extra_security_phone_success')
    else:
        current_app.logger.info(f'Could not verify phone code for {state.eppn}')
        return error_message('resetpw.phone-code-unknown')

    # XXX continue

    hashed = b64encode(hash_password(password)).decode('utf8')
    if hashed == session.reset_password.generated_password_hash:
        current_app.logger.info('Generated password used')
        current_app.stats.count(name='reset_password_generated_password_used')
    else:
        current_app.logger.info('Custom password used')
        current_app.stats.count(name='reset_password_custom_password_used')

    current_app.logger.info(f'Resetting password for user {state.eppn}')
    reset_user_password(state, password)
    current_app.logger.info(f'Password reset done, removing state for user {state.eppn}')
    current_app.password_reset_state_db.remove_state(state)
    return success_message('resetpw.pw-resetted')
