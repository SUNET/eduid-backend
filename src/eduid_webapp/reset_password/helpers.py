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
import math
import os
from typing import Union, Optional

import bcrypt
from flask import url_for
from flask import render_template
from flask_babel import gettext as _

from eduid_userdb.exceptions import UserHasNotCompletedSignup
from eduid_userdb.exceptions import DocumentDoesNotExist
from eduid_userdb.reset_password import ResetPasswordUser
from eduid_userdb.reset_password import ResetPasswordState
from eduid_userdb.reset_password import ResetPasswordEmailState
from eduid_userdb.reset_password import ResetPasswordEmailAndPhoneState
from eduid_userdb.logs import MailAddressProofing
from eduid_userdb.logs import PhoneNumberProofing
from eduid_common.api.utils import save_and_sync_user
from eduid_common.api.utils import get_unique_hash
from eduid_common.api.utils import get_short_hash
from eduid_common.authn.utils import generate_password
from eduid_common.authn.vccs import reset_password
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


class BadCode(Exception):
    """
    Exception to signal that the password reset code received is not valid.
    """
    def __init__(self, msg: str):
        self.msg = msg


def get_pwreset_state(email_code: str) -> ResetPasswordState:
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

    if isinstance(state, ResetPasswordEmailAndPhoneState) and state.phone_code.is_expired(sms_expiration_time):
        current_app.logger.info(f'Phone code expired for state: {email_code}')
        # Revert the state to EmailState to allow the user to choose extra security again
        current_app.password_reset_state_db.remove_state(state)
        state = ResetPasswordEmailState(eppn=state.eppn, email_address=state.email_address,
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
    state = ResetPasswordEmailState(eppn=user.eppn,
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


def send_mail(subject: str, to_addresses: List[str], text_template: str, html_template: str,
              context: Optional[dict] = None, reference: Optional[str] = None):
    """
    :param subject: subject text
    :param to_addresses: email addresses for the to field
    :param text_template: text message as a jinja template
    :param html_template: html message as a jinja template
    :param context: template context
    :param reference: Audit reference to help cross reference audit log and events
    """
    site_name = current_app.config.eduid_site_name
    site_url = current_app.config.eduid_site_url

    default_context = {
        "site_url": site_url,
        "site_name": site_name,
    }
    if not context:
        context = {}
    context.update(default_context)

    current_app.logger.debug(u'subject: {}'.format(subject))
    current_app.logger.debug(u'to addresses: {}'.format(to_addresses))
    text = render_template(text_template, **context)
    current_app.logger.debug(u'rendered text: {}'.format(text))
    html = render_template(html_template, **context)
    current_app.logger.debug(u'rendered html: {}'.format(html))
    current_app.mail_relay.sendmail(subject, to_addresses, text, html, reference)


def generate_suggested_password() -> str:
    """
    The suggested password is saved in session to avoid form hijacking
    """
    password_length = current_app.config.password_length

    password = generate_password(length=password_length)
    password = ' '.join([password[i*4: i*4+4] for i in range(0, math.ceil(len(password)/4))])

    return password


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


def extra_security_used(state: ResetPasswordState) -> bool:
    """
    Check if any extra security method was used

    :param state: Password reset state
    :type state: ResetPasswordState
    :return: True|False
    :rtype: bool
    """
    if isinstance(state, ResetPasswordEmailAndPhoneState):
        return state.email_code.is_verified and state.phone_code.is_verified

    return False


def reset_user_password(state: ResetPasswordState, password: str):
    """
    :param state: Password reset state
    :param password: Plain text password
    """
    vccs_url = current_app.config.vccs_url

    user = current_app.central_userdb.get_user_by_eppn(state.eppn, raise_on_missing=False)
    reset_password_user = ResetPasswordUser.from_user(user, private_userdb=current_app.private_userdb)

    # If no extra security is all verified information (except email addresses) is set to not verified
    if not extra_security_used(state):
        current_app.logger.info(f'No extra security used by user {state.eppn}')
        # Phone numbers
        verified_phone_numbers = reset_password_user.phone_numbers.verified.to_list()
        if verified_phone_numbers:
            current_app.logger.info(f'Unverifying phone numbers for user {state.eppn}')
            reset_password_user.phone_numbers.primary.is_primary = False
            for phone_number in verified_phone_numbers:
                phone_number.is_verified = False
                current_app.logger.debug(f'Phone number {phone_number.number} unverified')
        # NINs
        verified_nins = reset_password_user.nins.verified.to_list()
        if verified_nins:
            current_app.logger.info('Unverifying nins for user {state.eppn}')
            reset_password_user.nins.primary.is_primary = False
            for nin in verified_nins:
                nin.is_verified = False
                current_app.logger.debug('NIN {nin.number} unverified')

    reset_password_user = reset_password(reset_password_user, new_password=password,
                                   application='security', vccs_url=vccs_url)
    reset_password_user.terminated = False
    save_and_sync_user(reset_password_user)
    current_app.stats.count(name='security_password_reset', value=1)
    current_app.logger.info('Reset password successful for user {reset_password_user.eppn}')


def get_extra_security_alternatives(eppn: str) -> dict:
    """
    :param eppn: Users unique eppn
    :return: Dict of alternatives
    """
    alternatives = {}
    user = current_app.central_userdb.get_user_by_eppn(eppn, raise_on_missing=True)

    if user.phone_numbers.verified.count:
        verified_phone_numbers = [item.number for item in user.phone_numbers.verified.to_list()]
        alternatives['phone_numbers'] = verified_phone_numbers
    return alternatives


def mask_alternatives(alternatives: dict) -> dict:
    """
    :param alternatives: Extra security alternatives collected from user
    :return: Masked extra security alternatives
    """
    if alternatives:
        # Phone numbers
        masked_phone_numbers = []
        for phone_number in alternatives.get('phone_numbers', []):
            masked_number = '{}{}'.format('X'*(len(phone_number)-2), phone_number[len(phone_number)-2:])
            masked_phone_numbers.append(masked_number)

        alternatives['phone_numbers'] = masked_phone_numbers
    return alternatives


def verify_email_address(state: ResetPasswordEmailState) -> bool:
    """
    :param state: Password reset state
    """
    user = current_app.central_userdb.get_user_by_eppn(state.eppn,
                                                       raise_on_missing=False)
    if not user:
        current_app.logger.error(f'Could not find user {state.eppn}')
        return False

    proofing_element = MailAddressProofing(user, created_by='security',
                                           mail_address=state.email_address,
                                           reference=state.reference,
                                           proofing_version='2013v1')

    if current_app.proofing_log.save(proofing_element):
        state.email_code.is_verified = True
        current_app.password_reset_state_db.save(state)
        current_app.logger.info(f'Email code marked as used for {state.eppn}')
        return True

    return False


def send_verify_phone_code(state: ResetPasswordEmailState, phone_number: str):
    state = ResetPasswordEmailAndPhoneState.from_email_state(state,
                                            phone_number=phone_number,
                                            phone_code=get_short_hash())
    current_app.password_reset_state_db.save(state)
    template = 'reset_password_sms.txt.jinja2'
    context = {
        'verification_code': state.phone_code.code
    }
    send_sms(state.phone_number, template, context, state.reference)
    current_app.logger.info(f'Sent password reset sms to user {state.eppn}')
    current_app.logger.debug(f'Phone number: {state.phone_number}')


def send_sms(phone_number: str, text_template: str,
             context: Optional[dict] = None,
             reference: Optional[str] = None):
    """
    :param phone_number: the recipient of the sms
    :param text_template: message as a jinja template
    :param context: template context
    :param reference: Audit reference to help cross reference audit log and events
    """
    default_context = {
        "site_url": current_app.config.eduid_site_url,
        "site_name": current_app.config.eduid_site_name,
    }
    if context is None:
        context = {}
    context.update(default_context)

    message = render_template(text_template, **context)
    current_app.msg_relay.sendsms(phone_number, message, reference)


def verify_phone_number(state: ResetPasswordEmailAndPhoneState) -> bool:
    """
    :param state: Password reset state
    """

    user = current_app.central_userdb.get_user_by_eppn(state.eppn,
                                                       raise_on_missing=False)
    if not user:
        current_app.logger.error(f'Could not find user {state.eppn}')
        return False

    proofing_element = PhoneNumberProofing(user, created_by='security',
                                           phone_number=state.phone_number,
                                           reference=state.reference,
                                           proofing_version='2013v1')
    if current_app.proofing_log.save(proofing_element):
        state.phone_code.is_verified = True
        current_app.password_reset_state_db.save(state)
        current_app.logger.info('Phone code marked as used for {state.eppn}')
        return True

    return False
