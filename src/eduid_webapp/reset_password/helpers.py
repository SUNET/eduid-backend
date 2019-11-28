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
import os
from typing import Union

import bcrypt
from flask import url_for
from flask_babel import gettext as _

from eduid_userdb.exceptions import UserHasNotCompletedSignup
from eduid_common.api.utils import get_unique_hash
from eduid_userdb.security import PasswordResetState
from eduid_userdb.security import PasswordResetEmailAndPhoneState
from eduid_userdb.security import PasswordResetEmailState
from eduid_webapp.security.helpers import send_mail
from eduid_userdb.exceptions import DocumentDoesNotExist
from eduid_webapp.reset_password.app import current_reset_password_app as current_app


def success_message(message: Union[str, bytes]) -> dict:
    return {
        '_status': 'ok',
        'message': str(message)
    }


def error_message(message: Union[str, bytes]) -> dict:
    return {
        '_status': 'error',
        'message': str(message)
    }


def get_pwreset_state(email_code: str) -> PasswordResetState:
    """
    get the password reset state for the provided code

    raises BadCode in case of problems
    """
    mail_expiration_time = current_app.config.email_code_timeout
    sms_expiration_time = current_app.config.phone_code_timeout
    try:
        state = current_app.password_reset_state_db.get_state_by_email_code(email_code)
        current_app.logger.debug(f'Found state using email_code {email_code}: {state}')
    except DocumentDoesNotExist:
        current_app.logger.info('State not found: {email_code}')
        raise BadCode('resetpw.unknown-code')

    if state.email_code.is_expired(mail_expiration_time):
        current_app.logger.info(f'State expired: {email_code}')
        raise BadCode('resetpw.expired-email-code')

    if isinstance(state, PasswordResetEmailAndPhoneState) and state.phone_code.is_expired(sms_expiration_time):
        current_app.logger.info(f'Phone code expired for state: {email_code}')
        # Revert the state to EmailState to allow the user to choose extra security again
        current_app.password_reset_state_db.remove_state(state)
        state = PasswordResetEmailState(eppn=state.eppn, email_address=state.email_address,
                                        email_code=state.email_code)
        current_app.password_reset_state_db.save(state)
        raise BadCode('resetpw.expired-sms-code')

    return state


def send_password_reset_mail(email_address: str):
    """
    :param email_address: User input for password reset
    """
    try:
        user = current_app.central_userdb.get_user_by_mail(email_address,
                                                        raise_on_missing=False)
    except UserHasNotCompletedSignup:
        # Old bug where incomplete signup users where written to the central db
        user = None
    if not user:
        current_app.logger.info(f"Found no user with the following "
                                 "address: {email_address}.")
        return None
    state = PasswordResetEmailState(eppn=user.eppn,
                                    email_address=email_address,
                                    email_code=get_unique_hash())
    current_app.password_reset_state_db.save(state)
    text_template = 'reset_password_email.txt.jinja2'
    html_template = 'reset_password_email.html.jinja2'
    to_addresses = [address.email for address in user.mail_addresses.verified.to_list()]

    pwreset_timeout = current_app.config.email_code_timeout // 60 // 60  # seconds to hours
    context = {
        'reset_password_link': url_for('reset_password.set_new_pw',
                                       email_code=state.email_code.code,
                                       _external=True),
        'password_reset_timeout': pwreset_timeout
    }
    subject = _('Reset password')
    send_mail(subject, to_addresses, text_template,
              html_template, context, state.reference)
    current_app.logger.info(f'Sent password reset email to user {state.eppn}')
    current_app.logger.debug(f'Mail addresses: {to_addresses}')


def hash_password(password: str,
                  salt: str = None,
                  strip_whitespace: bool = True) -> bytes:
    """
    :param password: string, password as plaintext
    :param salt: string or None, NDNv1H1 salt to be used for pre-hashing
                 (if None, one will be generated.)
    :param strip_whitespace: boolean, Remove all whitespace from input
    """
    if salt is None:
        salt_length = current_app.config.password_salt_length
        key_length = current_app.config.password_hash_length
        rounds = current_app.config.password_generation_rounds
        random = os.urandom(salt_length)
        random_str = random.hex()
        salt = f"$NDNv1H1${random_str}${key_length}${rounds}$"

    if not salt.startswith('$NDNv1H1$'):
        raise ValueError('Invalid salt (not NDNv1H1)')

    salt, key_length, rounds = decode_salt(salt)

    if strip_whitespace:
        password = ''.join(password.split())

    T1 = bytes(f"{len(password)}{password}", 'utf-8')

    return bcrypt.kdf(T1, salt, key_length, rounds)


def decode_salt(salt: str):
    """
    Function to decode a NDNv1H1 salt.
    """
    _, version, salt, desired_key_length, rounds, _ = salt.split('$')
    if version == 'NDNv1H1':
        salt = bytes().fromhex(salt)
        return salt, int(desired_key_length), int(rounds)
    raise NotImplementedError('Unknown hashing scheme')
