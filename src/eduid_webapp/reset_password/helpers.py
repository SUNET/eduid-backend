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
#     3. Neither the name of the SUNET nor the names of its
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
from dataclasses import dataclass
from enum import unique
from typing import Any, Dict, List, Optional, Union

import bcrypt
from flask import render_template
from flask_babel import gettext as _

from eduid_common.api.exceptions import MailTaskFailed
from eduid_common.api.helpers import send_mail
from eduid_common.api.messages import FluxData, TranslatableMsg, error_response, success_response
from eduid_common.api.utils import get_short_hash, get_unique_hash, save_and_sync_user, urlappend
from eduid_common.api.validation import is_valid_password
from eduid_common.authn import fido_tokens
from eduid_common.authn.utils import generate_password
from eduid_common.authn.vccs import reset_password
from eduid_common.session import session
from eduid_userdb.exceptions import DocumentDoesNotExist, UserDoesNotExist
from eduid_userdb.logs import MailAddressProofing, PhoneNumberProofing
from eduid_userdb.reset_password import (
    ResetPasswordEmailAndPhoneState,
    ResetPasswordEmailState,
    ResetPasswordState,
    ResetPasswordUser,
)
from eduid_userdb.user import User

from eduid_webapp.reset_password.app import current_reset_password_app as current_app


@unique
class ResetPwMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # The user has sent a code that corresponds to no known password reset
    # request
    state_not_found = 'resetpw.state-not-found'
    # Some required input data is empty
    missing_data = 'resetpw.missing-data'
    # The user has sent an SMS'ed code that corresponds to no known password
    # reset request
    unknown_phone_code = 'resetpw.phone-code-unknown'
    # The user has sent a code that has expired
    expired_email_code = 'resetpw.expired-email-code'
    # The user has sent an SMS'ed code that has expired
    expired_phone_code = 'resetpw.expired-phone-code'
    # There was some problem sending the email with the code.
    email_send_failure = 'resetpw.email-send-failure'
    # A new code has been generated and sent by email successfully
    reset_pw_initialized = 'resetpw.reset-pw-initialized'
    # The password has been successfully reset
    pw_reset_success = 'resetpw.pw-reset-success'
    # The password has _NOT_ been successfully reset
    pw_reset_fail = 'resetpw.pw-reset-fail'
    # There was some problem sending the SMS with the (extra security) code.
    send_sms_throttled = 'resetpw.sms-throttled'
    # Sending the SMS with the (extra security) code has been throttled.
    send_sms_failure = 'resetpw.sms-failed'
    # A new (extra security) code has been generated and sent by SMS
    # successfully
    send_sms_success = 'resetpw.sms-success'
    # The phone number has not been verified. Should not happen.
    phone_invalid = 'resetpw.phone-invalid'
    # No user was found corresponding to the password reset state. Should not
    # happen.
    user_not_found = 'resetpw.user-not-found'
    # The email address has not been verified. Should not happen.
    email_not_validated = 'resetpw.email-not-validated'
    # User has not completed signup
    invalid_user = 'resetpw.incomplete-user'
    # the user has chosen extra security with a security key but has failed to
    # produce evidence of it.
    hwtoken_fail = 'security-key-fail'
    # No webauthn data in the request
    mfa_no_data = 'mfa.no-request-data'
    # extra security with fido tokens failed - wrong token
    fido_token_fail = 'resetpw.fido-token-fail'
    # The password chosen is too weak
    resetpw_weak = 'resetpw.weak-password'
    # email address validation error
    invalid_email = 'Invalid email address'


class StateException(Exception):
    def __init__(self, msg: Optional[TranslatableMsg] = None):
        self.msg = msg


@dataclass
class ResetPasswordContext:
    state: Union[ResetPasswordEmailState, ResetPasswordEmailAndPhoneState]
    user: User


def get_context(email_code: str) -> ResetPasswordContext:
    """
    Use a email code to load reset-password state from the database.

    :param email_code: User supplied password reset code
    :return: ResetPasswordContext instance
    """
    state = get_pwreset_state(email_code)

    try:
        user = current_app.central_userdb.get_user_by_eppn(state.eppn, raise_on_missing=True)
    except UserDoesNotExist as e:
        # User has been removed before reset password was completed
        current_app.logger.error(f'User not found for state {state.email_code}: {e}')
        raise StateException(msg=ResetPwMsg.user_not_found)

    return ResetPasswordContext(state=state, user=user)


def get_pwreset_state(email_code: str) -> Union[ResetPasswordEmailState, ResetPasswordEmailAndPhoneState]:
    """
    get the password reset state for the provided code

    raises BadCode in case of problems
    """
    mail_expiration_time = current_app.conf.email_code_timeout
    sms_expiration_time = current_app.conf.phone_code_timeout
    try:
        state = current_app.password_reset_state_db.get_state_by_email_code(email_code, raise_on_missing=True)
        current_app.logger.debug(f'Found state using email_code {email_code}: {state}')
        assert state is not None  # assure mypy, raise_on_missing=True will make this never happen
    except DocumentDoesNotExist:
        current_app.logger.info(f'State not found: {email_code}')
        raise StateException(msg=ResetPwMsg.state_not_found)

    if state.email_code.is_expired(mail_expiration_time):
        current_app.logger.info(f'State expired: {email_code}')
        raise StateException(msg=ResetPwMsg.expired_email_code)

    if isinstance(state, ResetPasswordEmailAndPhoneState) and state.phone_code.is_expired(sms_expiration_time):
        current_app.logger.info(f'Phone code expired for state: {email_code}')
        # Revert the state to EmailState to allow the user to choose extra security again
        current_app.password_reset_state_db.remove_state(state)
        state = ResetPasswordEmailState(eppn=state.eppn, email_address=state.email_address, email_code=state.email_code)
        current_app.password_reset_state_db.save(state)
        raise StateException(msg=ResetPwMsg.expired_phone_code)
    return state


def is_generated_password(password: str) -> bool:
    hashed = session.reset_password.generated_password_hash
    if check_password(password, hashed):
        current_app.logger.info('Generated password used')
        current_app.stats.count(name='generated_password_used')
        return True
    current_app.logger.info('Custom password used')
    current_app.stats.count(name='custom_password_used')
    return False


def send_password_reset_mail(email_address: str) -> None:
    """
    :param email_address: User input for password reset
    """
    try:
        user = current_app.central_userdb.get_user_by_mail(email_address)
    except DocumentDoesNotExist:
        current_app.logger.error(f'Cannot send reset password mail to an unknown email address: {email_address}')
        return None

    # User found, create a new state
    state = ResetPasswordEmailState(eppn=user.eppn, email_address=email_address, email_code=get_unique_hash())
    current_app.password_reset_state_db.save(state)

    # Send email
    text_template = 'reset_password_email.txt.jinja2'
    html_template = 'reset_password_email.html.jinja2'
    to_addresses = [address.email for address in user.mail_addresses.verified.to_list()]
    pwreset_timeout = current_app.conf.email_code_timeout // 60 // 60  # seconds to hours
    # We must send the user to an url that does not correspond to a flask view,
    # but to a js bundle (i.e. a flask view in a *different* app)
    resetpw_link = urlappend(current_app.conf.password_reset_link, f'code/{state.email_code.code}')
    context = {'reset_password_link': resetpw_link, 'password_reset_timeout': pwreset_timeout}
    subject = _('Reset password')
    try:
        send_mail(subject, to_addresses, text_template, html_template, current_app, context, state.reference)
    except MailTaskFailed as e:
        current_app.logger.error(f'Sending password reset e-mail failed: {e}')
        current_app.logger.debug(f'email address: {email_address}')
        raise e

    current_app.logger.info(f'Sent password reset email')
    current_app.logger.debug(f'Mail addresses: {to_addresses}')


def generate_suggested_password(password_length: int) -> str:
    """
    The suggested password is hashed and saved in session to avoid form hijacking
    """
    password = generate_password(length=password_length)
    password = ' '.join([password[i * 4 : i * 4 + 4] for i in range(0, math.ceil(len(password) / 4))])

    return password


def hash_password(password: str) -> str:
    """
    Return a hash of the provided password

    :param password: password as plaintext
    """
    password = ''.join(password.split())
    return bcrypt.hashpw(password, bcrypt.gensalt())


def check_password(password: str, hashed: Optional[str]) -> bool:
    """
    Check that the provided password corresponds to the provided hash
    """
    if hashed is None:
        return False
    password = ''.join(password.split())
    return bcrypt.checkpw(password, hashed)


def extra_security_used(state: ResetPasswordState, security_key_used: bool = False) -> bool:
    """
    Check if any extra security method was used

    :param state: Password reset state
    :param security_key_used: If a security key was used
    :return: True|False
    """
    if security_key_used:
        return True
    if isinstance(state, ResetPasswordEmailAndPhoneState):
        return state.email_code.is_verified and state.phone_code.is_verified
    return False


def unverify_user(user: ResetPasswordUser) -> None:
    """
    :param user: User object

    Unverify the users verified information (phone numbers and NIN)
    """
    # Phone numbers
    verified_phone_numbers = user.phone_numbers.verified.to_list()
    if verified_phone_numbers:
        current_app.logger.info(f'Unverifying phone numbers for user {user}')
        user.phone_numbers.primary.is_primary = False
        for phone_number in verified_phone_numbers:
            phone_number.is_verified = False
            current_app.logger.info('Phone number unverified')
            current_app.logger.debug(f'Phone number: {phone_number.number}')
            current_app.stats.count(name='unverified_phone', value=1)
    # NINs
    verified_nins = user.nins.verified.to_list()
    if verified_nins:
        current_app.logger.info(f'Unverifying nins for user {user}')
        user.nins.primary.is_primary = False
        for nin in verified_nins:
            nin.is_verified = False
            current_app.logger.info('NIN unverified')
            current_app.logger.debug(f'NIN: {nin.number}')
            current_app.stats.count(name='unverified_nin', value=1)


def reset_user_password(
    user: User, state: ResetPasswordState, password: str, security_key_used: bool = False
) -> FluxData:
    """
    :param user: the user
    :param state: Password reset state
    :param password: Plain text password
    :param security_key_used: If a security key was used as extra security
    """
    # Check the the password complexity is enough
    user_info = get_zxcvbn_terms(user)
    try:
        is_valid_password(password, user_info=user_info, min_entropy=current_app.conf.password_entropy)
    except ValueError:
        return error_response(message=ResetPwMsg.resetpw_weak)

    reset_password_user = ResetPasswordUser.from_user(user, private_userdb=current_app.private_userdb)

    # If no extra security is used, all verified information (except email addresses) is set to not verified
    if not extra_security_used(state, security_key_used):
        current_app.stats.count(name='no_extra_security', value=1)
        current_app.logger.info(f'No extra security used by user {user}')
        unverify_user(reset_password_user)

    _res = reset_password(
        reset_password_user,
        new_password=password,
        is_generated=is_generated_password(password=password),
        application='security',
        vccs_url=current_app.conf.vccs_url,
    )

    if not _res:
        # Uh oh, reset password failed. Credentials _might_ have been reset in the backend but we don't know.
        current_app.stats.count(name='password_reset_fail', value=1)
        current_app.logger.error(f'Reset password failed for user {reset_password_user}')
        return error_response(message=ResetPwMsg.pw_reset_fail)

    reset_password_user.terminated = None
    save_and_sync_user(reset_password_user)
    current_app.stats.count(name='password_reset_success', value=1)
    current_app.logger.info(f'Reset password successful for user {reset_password_user}')

    current_app.logger.info(f'Password reset done, removing state for {user}')
    current_app.password_reset_state_db.remove_state(state)
    return success_response(message=ResetPwMsg.pw_reset_success)


def get_extra_security_alternatives(user: User, session_prefix: str) -> dict:
    """
    :param user: The user
    :param session_prefix: session prefix
    :return: Dict of alternatives
    """
    alternatives: Dict[str, Any] = {}

    if user.phone_numbers.verified.count:
        verified_phone_numbers = [
            {'number': item.number, 'index': n} for n, item in enumerate(user.phone_numbers.verified.to_list())
        ]
        alternatives['phone_numbers'] = verified_phone_numbers

    tokens = fido_tokens.get_user_credentials(user)

    if tokens:
        alternatives['tokens'] = fido_tokens.start_token_verification(
            user, session_prefix, current_app.conf.fido2_rp_id
        )

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
            number = phone_number['number']
            masked_number = '{}{}'.format('X' * (len(number) - 2), number[len(number) - 2 :])
            masked_phone_numbers.append({'number': masked_number, 'index': phone_number['index']})

        alternatives['phone_numbers'] = masked_phone_numbers
    return alternatives


def verify_email_address(state: ResetPasswordEmailState) -> bool:
    """
    :param state: Password reset state
    """
    user = current_app.central_userdb.get_user_by_eppn(state.eppn, raise_on_missing=False)
    if not user:
        current_app.logger.error(f'Could not find user {user}')
        return False

    proofing_element = MailAddressProofing(
        eppn=user.eppn,
        created_by='security',
        mail_address=state.email_address,
        reference=state.reference,
        proofing_version='2013v1',
    )

    if current_app.proofing_log.save(proofing_element):
        state.email_code.is_verified = True
        current_app.password_reset_state_db.save(state)
        current_app.logger.info(f'Email code marked as used for {user}')
        return True

    return False


def send_verify_phone_code(state: ResetPasswordEmailState, phone_number: str):
    phone_state = ResetPasswordEmailAndPhoneState.from_email_state(
        state, phone_number=phone_number, phone_code=get_short_hash()
    )
    current_app.password_reset_state_db.save(phone_state)

    template = 'reset_password_sms.txt.jinja2'
    context = {'verification_code': phone_state.phone_code.code}
    send_sms(phone_state.phone_number, template, context, phone_state.reference)
    current_app.logger.info(f'Sent password reset sms to user with eppn: {state.eppn}')
    current_app.logger.debug(f'Sent password reset sms with code: {phone_state.phone_code.code}')
    current_app.logger.debug(f'Phone number: {phone_state.phone_number}')


def send_sms(phone_number: str, text_template: str, context: Optional[dict] = None, reference: Optional[str] = None):
    """
    :param phone_number: the recipient of the sms
    :param text_template: message as a jinja template
    :param context: template context
    :param reference: Audit reference to help cross reference audit log and events
    """
    default_context = {
        "site_url": current_app.conf.eduid_site_url,
        "site_name": current_app.conf.eduid_site_name,
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

    user = current_app.central_userdb.get_user_by_eppn(state.eppn, raise_on_missing=False)
    if not user:
        current_app.logger.error(f'Could not find user {user}')
        return False

    proofing_element = PhoneNumberProofing(
        eppn=user.eppn,
        created_by='security',
        phone_number=state.phone_number,
        reference=state.reference,
        proofing_version='2013v1',
    )
    if current_app.proofing_log.save(proofing_element):
        state.phone_code.is_verified = True
        current_app.password_reset_state_db.save(state)
        current_app.logger.info(f'Phone code marked as used for {user}')
        return True

    return False


def compile_credential_list(user: ResetPasswordUser) -> list:
    """
    :return: List of augmented credentials
    """
    credentials = []
    authn_info = current_app.authninfo_db.get_authn_info(user)
    credentials_used = session.get('eduidIdPCredentialsUsed', list())
    # In the development environment credentials_used gets set to None
    if credentials_used is None:
        credentials_used = []
    for credential in user.credentials.to_list():
        credential_dict = credential.to_dict()
        credential_dict['key'] = credential.key
        if credential.key in credentials_used:
            credential_dict['used_for_login'] = True
        if credential.is_verified:
            credential_dict['verified'] = True
        credential_dict.update(authn_info[credential.key])
        credentials.append(credential_dict)
    return credentials


def get_zxcvbn_terms(user: User) -> List[str]:
    """
    Combine known data that is bad for a password to a list for zxcvbn.

    :param user: User
    :return: List of user info
    """
    user_input = []
    # Personal info
    if user.display_name:
        for part in user.display_name.split():
            user_input.append(''.join(part.split()))
    if user.given_name:
        user_input.append(user.given_name)
    if user.surname:
        user_input.append(user.surname)

    # Mail addresses
    if user.mail_addresses.count:
        for item in user.mail_addresses.to_list():
            user_input.append(item.email.split('@')[0])

    return user_input
