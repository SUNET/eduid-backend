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
import datetime
import math
from dataclasses import dataclass
from enum import unique
from typing import Any, Dict, List, Mapping, Optional, Union

from flask import render_template
from flask_babel import gettext as _

from eduid.common.config.base import EduidEnvironment
from eduid.common.utils import urlappend
from eduid.userdb.exceptions import DocumentDoesNotExist, UserDoesNotExist
from eduid.userdb.logs import MailAddressProofing, PhoneNumberProofing
from eduid.userdb.reset_password import ResetPasswordEmailAndPhoneState, ResetPasswordEmailState, ResetPasswordUser
from eduid.userdb.reset_password.element import CodeElement
from eduid.userdb.user import User
from eduid.webapp.common.api.exceptions import MailTaskFailed, ThrottledException
from eduid.webapp.common.api.helpers import send_mail
from eduid.webapp.common.api.messages import FluxData, TranslatableMsg, error_response, success_response
from eduid.webapp.common.api.utils import check_password_hash, get_short_hash, get_unique_hash, save_and_sync_user
from eduid.webapp.common.api.validation import is_valid_password
from eduid.webapp.common.authn import fido_tokens
from eduid.webapp.common.authn.utils import generate_password
from eduid.webapp.common.authn.vccs import reset_password
from eduid.webapp.common.session import session
from eduid.webapp.reset_password.app import current_reset_password_app as current_app


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
    # The phone number choice is out of bounds
    unknown_phone_number = 'resetpw.phone-number-unknown'
    # The user has sent a code that has expired
    expired_email_code = 'resetpw.expired-email-code'
    # The user has sent an SMS'ed code that has expired
    expired_phone_code = 'resetpw.expired-phone-code'
    # There was some problem sending the email with the code.
    email_send_failure = 'resetpw.email-send-failure'
    # A new code has been generated and sent by email successfully
    email_send_throttled = 'resetpw.email-throttled'
    # Sending the email has been throttled.
    reset_pw_initialized = 'resetpw.reset-pw-initialized'
    # The password has been successfully reset
    pw_reset_success = 'resetpw.pw-reset-success'
    # The password has _NOT_ been successfully reset
    pw_reset_fail = 'resetpw.pw-reset-fail'
    # There was some problem sending the SMS with the (extra security) code.
    send_sms_throttled = 'resetpw.sms-throttled'
    # Sending the SMS with the (extra security) code has been throttled.
    send_sms_failure = 'resetpw.send-sms-failed'
    # A new (extra security) code has been generated and sent by SMS
    # successfully
    send_sms_success = 'resetpw.send-sms-success'
    # The phone number has not been verified. Should not happen.
    phone_invalid = 'resetpw.phone-invalid'
    # No user was found corresponding to the password reset state. Should not
    # happen.
    user_not_found = 'resetpw.user-not-found'
    # The email address has not been verified. Should not happen.
    email_not_validated = 'resetpw.email-not-validated'
    # User has not completed signup
    invalid_user = 'resetpw.invalid-user'
    # extra security with fido tokens failed - wrong token
    fido_token_fail = 'resetpw.fido-token-fail'
    # extra security with external MFA service failed
    external_mfa_fail = 'resetpw.external-mfa-fail'
    # The password chosen is too weak
    resetpw_weak = 'resetpw.weak-password'
    # The browser already has a session for another user
    invalid_session = 'resetpw.invalid_session'


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

    user = current_app.central_userdb.get_user_by_eppn(state.eppn, raise_on_missing=False)
    if not user:
        # User has been removed before reset password was completed
        current_app.logger.error(f'User not found for state {state.email_code}')
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
    if check_password_hash(password, session.reset_password.generated_password_hash):
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
    user = current_app.central_userdb.get_user_by_mail(email_address, raise_on_missing=False)
    if not user:
        current_app.logger.error(f'Cannot send reset password mail to an unknown email address: {email_address}')
        raise UserDoesNotExist(f'User with e-mail address {email_address} not found')

    # User found, check if a state already exists
    state = current_app.password_reset_state_db.get_state_by_eppn(eppn=user.eppn, raise_on_missing=False)
    if state and not state.email_code.is_expired(timeout_seconds=current_app.conf.email_code_timeout):
        # Let the user only send one mail every throttle_resend_seconds
        if state.is_throttled(current_app.conf.throttle_resend_seconds):
            raise ThrottledException()
        # If a state is found and not expired, just send another message with the same code
        # Update created_ts to give the user another email_code_timeout seconds to complete the password reset
        state.email_code.created_ts = datetime.datetime.utcnow()
    else:
        # create a new state
        state = ResetPasswordEmailState(
            eppn=user.eppn,
            email_address=email_address,
            email_code=CodeElement(code=get_unique_hash(), created_by=current_app.conf.app_name, is_verified=False),
        )
    current_app.password_reset_state_db.save(state)

    # Send email
    text_template = 'reset_password_email.txt.jinja2'
    html_template = 'reset_password_email.html.jinja2'
    to_addresses = [address.email for address in user.mail_addresses.verified]
    pwreset_timeout = current_app.conf.email_code_timeout // 60 // 60  # seconds to hours
    # We must send the user to an url that does not correspond to a flask view,
    # but to a js bundle (i.e. a flask view in a *different* app)
    resetpw_link = urlappend(current_app.conf.password_reset_link, state.email_code.code)
    context = {'reset_password_link': resetpw_link, 'password_reset_timeout': pwreset_timeout}
    subject = _('Reset password')
    try:
        send_mail(subject, to_addresses, text_template, html_template, current_app, context, state.reference)
    except MailTaskFailed as e:
        current_app.logger.error(f'Sending password reset e-mail failed')
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


def extra_security_used(
    state: Union[ResetPasswordEmailState, ResetPasswordEmailAndPhoneState], mfa_used: bool = False
) -> bool:
    """
    Check if any extra security method was used

    :param state: Password reset state
    :param mfa_used: If a security key or external MFA was used
    :return: True|False
    """
    if state.email_code.is_verified and mfa_used:
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
    verified_phone_numbers = user.phone_numbers.verified
    if verified_phone_numbers:
        current_app.logger.info(f'Unverifying phone numbers for user {user}')
        if user.phone_numbers.primary:
            user.phone_numbers.primary.is_primary = False
        for phone_number in verified_phone_numbers:
            phone_number.is_verified = False
            current_app.logger.info('Phone number unverified')
            current_app.logger.debug(f'Phone number: {phone_number.number}')
            current_app.stats.count(name='unverified_phone', value=1)
    # NINs
    verified_nins = user.nins.verified
    if verified_nins:
        current_app.logger.info(f'Unverifying nins for user {user}')
        if user.nins.primary:
            user.nins.primary.is_primary = False
        for nin in verified_nins:
            nin.is_verified = False
            current_app.logger.info('NIN unverified')
            current_app.logger.debug(f'NIN: {nin.number}')
            current_app.stats.count(name='unverified_nin', value=1)


def reset_user_password(
    user: User,
    state: Union[ResetPasswordEmailState, ResetPasswordEmailAndPhoneState],
    password: str,
    mfa_used: bool = False,
) -> FluxData:
    """
    :param user: the user
    :param state: Password reset state
    :param password: Plain text password
    :param mfa_used: If a security key or external MFA was used as extra security
    """
    # Check the the password complexity is enough
    user_info = get_zxcvbn_terms(user)
    try:
        is_valid_password(
            password,
            user_info=user_info,
            min_entropy=current_app.conf.password_entropy,
            min_score=current_app.conf.min_zxcvbn_score,
        )
    except ValueError:
        return error_response(message=ResetPwMsg.resetpw_weak)

    reset_password_user = ResetPasswordUser.from_user(user, private_userdb=current_app.private_userdb)

    # If no extra security is used, all verified information (except email addresses) is set to not verified
    if not extra_security_used(state, mfa_used):
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

    # Undo termination if user is terminated
    if reset_password_user.terminated is not None:
        current_app.logger.info(f'Revoking termination for user: {user.terminated}')
        reset_password_user.terminated = None

    save_and_sync_user(reset_password_user)
    current_app.stats.count(name='password_reset_success', value=1)
    current_app.logger.info(f'Reset password successful for user {reset_password_user}')

    current_app.logger.info(f'Password reset done, removing state for {user}')
    current_app.password_reset_state_db.remove_state(state)
    return success_response(message=ResetPwMsg.pw_reset_success)


def get_extra_security_alternatives(user: User) -> dict:
    """
    :param user: The user
    :return: Dict of alternatives
    """
    alternatives: Dict[str, Any] = {}

    if user.nins.verified:
        alternatives['external_mfa'] = True

    if user.phone_numbers.verified:
        verified_phone_numbers = [
            {'number': item.number, 'index': n} for n, item in enumerate(user.phone_numbers.verified)
        ]
        alternatives['phone_numbers'] = verified_phone_numbers

    tokens = fido_tokens.get_user_credentials(user)

    if tokens:
        alternatives['tokens'] = fido_tokens.start_token_verification(
            user, current_app.conf.fido2_rp_id, session.mfa_action
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
    send_sms(
        phone_number=phone_state.phone_number, text_template=template, reference=phone_state.reference, context=context
    )
    current_app.logger.info(f'Sent password reset sms to user with eppn: {state.eppn}')
    if current_app.conf.debug and current_app.conf.environment in [EduidEnvironment.staging, EduidEnvironment.dev]:
        current_app.logger.debug(f'Sent password reset sms with code: {phone_state.phone_code.code}')
    current_app.logger.debug(f'Phone number: {phone_state.phone_number}')


def send_sms(phone_number: str, text_template: str, reference: str, context: Optional[Mapping[str, Any]] = None):
    """
    :param phone_number: the recipient of the sms
    :param text_template: message as a jinja template
    :param context: template context
    :param reference: Audit reference to help cross reference audit log and events
    """
    _context = {
        'site_url': current_app.conf.eduid_site_url,
        'site_name': current_app.conf.eduid_site_name,
    }
    if context is not None:
        _context.update(context)

    message = render_template(text_template, **_context)
    current_app.msg_relay.sendsms(recipient=phone_number, message=message, reference=reference)


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
