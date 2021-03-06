# -*- coding: utf-8 -*-


from datetime import datetime
from enum import unique
from typing import Optional

from flask import render_template, url_for
from flask_babel import gettext as _

from eduid.common.decorators import deprecated
from eduid.userdb.exceptions import UserHasNotCompletedSignup
from eduid.userdb.logs import MailAddressProofing, PhoneNumberProofing
from eduid.userdb.security import PasswordResetEmailAndPhoneState, PasswordResetEmailState, SecurityUser
from eduid.webapp.common.api.helpers import send_mail
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.api.utils import get_short_hash, get_unique_hash, save_and_sync_user
from eduid.webapp.common.authn.utils import generate_password
from eduid.webapp.common.authn.vccs import reset_password
from eduid.webapp.common.session import session
from eduid.webapp.security.app import current_security_app as current_app
from eduid.webapp.security.schemas import ConvertRegisteredKeys

__author__ = 'lundberg'


@unique
class SecurityMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # Too much time passed since re-authn for account termination
    stale_reauthn = 'security.stale_authn_info'
    # No reauthn
    no_reauthn = 'security.no_reauthn'
    # removing a verified NIN is not allowed
    rm_verified = 'nins.verified_no_rm'
    # success removing nin
    rm_success = 'nins.success_removal'
    # the user already has the nin
    already_exists = 'nins.already_exists'
    # success adding a new nin
    add_success = 'nins.successfully_added'
    # The user tried to register more than the allowed number of tokens
    max_tokens = 'security.u2f.max_allowed_tokens'
    max_webauthn = 'security.webauthn.max_allowed_tokens'
    # missing u2f enrollment data
    missing_data = 'security.u2f.missing_enrollment_data'
    # successfully registered u2f token
    u2f_registered = 'security.u2f_register_success'
    # No u2f tokens found for the user
    no_u2f = 'security.u2f.no_token_found'
    # no challenge data found in session during u2f token verification
    no_challenge = 'security.u2f.missing_challenge_data'
    # u2f token not found in user
    no_token = 'security.u2f.missing_token'
    # the description provided for the token is too long
    long_desc = 'security.u2f.description_to_long'
    # success removing u2f token
    rm_u2f_success = 'security.u2f-token-removed'
    # the account has to have personal data to be able to register webauthn data
    no_pdata = 'security.webauthn-missing-pdata'
    # success registering webauthn token
    webauthn_success = 'security.webauthn_register_success'
    # It is not allowed to remove the last webauthn credential left
    no_last = 'security.webauthn-noremove-last'
    # Success removing webauthn token
    rm_webauthn = 'security.webauthn-token-removed'
    # token to remove not found
    no_webauthn = 'security.webauthn-token-notfound'
    # old_password or new_password missing
    chpass_no_data = 'security.change_password_no_data'
    # weak password
    chpass_weak = 'security.change_password_weak'
    # wrong old password
    unrecognized_pw = 'security.change_password_wrong_old_password'
    # change password successfully completed
    chpass_password_changed = 'security.change_password_complete'


def credentials_to_registered_keys(user_u2f_tokens):
    """
    :param user_u2f_tokens: List of users U2F credentials
    :type user_u2f_tokens: eduid.userdb.credentials.CredentialList

    :return: List of registered keys
    :rtype: list
    """
    u2f_dicts = user_u2f_tokens.to_list_of_dicts()
    data = ConvertRegisteredKeys().dump({'registered_keys': u2f_dicts})
    return data['registered_keys']


def compile_credential_list(security_user):
    """
    :param security_user: User
    :type security_user: eduid.userdb.security.SecurityUser
    :return: List of augmented credentials
    :rtype: list
    """
    credentials = []
    authn_info = current_app.authninfo_db.get_authn_info(security_user)
    credentials_used = session.get('eduidIdPCredentialsUsed', list())
    # In the development environment credentials_used gets set to None
    if credentials_used is None:
        credentials_used = []
    for credential in security_user.credentials.to_list():
        credential_dict = credential.to_dict()
        credential_dict['key'] = credential.key
        if credential.key in credentials_used:
            credential_dict['used_for_login'] = True
        if credential.is_verified:
            credential_dict['verified'] = True
        credential_dict.update(authn_info[credential.key])
        credentials.append(credential_dict)
    return credentials


def remove_nin_from_user(security_user, nin):
    """
    :param security_user: Private userdb user
    :param nin: NIN to remove

    :type security_user: eduid.userdb.security.SecurityUser
    :type nin: str

    :return: None
    """
    if security_user.nins.find(nin):
        security_user.nins.remove(nin)
        security_user.modified_ts = datetime.utcnow()
        # Save user to private db
        current_app.private_userdb.save(security_user, check_sync=False)
        # Ask am to sync user to central db
        current_app.logger.debug('Request sync for user {!s}'.format(security_user))
        result = current_app.am_relay.request_user_sync(security_user)
        current_app.logger.info('Sync result for user {!s}: {!s}'.format(security_user, result))
    else:
        current_app.logger.info("Can't remove NIN - NIN not found")
        current_app.logger.info("NIN: {}".format(nin))


@deprecated("Remove once the password reset views are served from their own webapp")
def generate_suggested_password():
    """
    The suggested password is saved in session to avoid form hijacking
    """
    password_length = current_app.conf.password_length

    password = generate_password(length=password_length)
    password = ' '.join([password[i * 4 : i * 4 + 4] for i in range(0, int(len(password) / 4))])

    return password


@deprecated("Remove once the password reset views are served from their own webapp")
def send_sms(phone_number: str, text_template: str, reference: str, context: Optional[dict] = None):
    """
    :param phone_number: the recipient of the sms
    :param text_template: message as a jinja template
    :param context: template context
    :param reference: Audit reference to help cross reference audit log and events
    """
    site_name = current_app.conf.eduid_site_name
    site_url = current_app.conf.eduid_site_url

    default_context = {
        "site_url": site_url,
        "site_name": site_name,
    }
    if not context:
        context = {}
    context.update(default_context)

    message = render_template(text_template, **context)
    current_app.msg_relay.sendsms(phone_number, message, reference)


def send_termination_mail(user):
    """
    :param user: User object
    :type user: User

    Sends a termination mail to all verified mail addresses for the user.
    """
    subject = _('Terminate account')
    text_template = "termination_email.txt.jinja2"
    html_template = "termination_email.html.jinja2"
    to_addresses = [address.email for address in user.mail_addresses.verified.to_list()]
    send_mail(subject, to_addresses, text_template, html_template, current_app)
    current_app.logger.info("Sent termination email to user.")


@deprecated("Remove once the password reset views are served from their own webapp")
def send_password_reset_mail(email_address):
    """
    :param email_address: User input for password reset
    :type email_address: six.string_types
    :return:
    :rtype:
    """
    try:
        user = current_app.central_userdb.get_user_by_mail(email_address, raise_on_missing=False)
    except UserHasNotCompletedSignup:
        # Old bug where incomplete signup users where written to the central db
        user = None
    if not user:
        current_app.logger.info("Found no user with the following address: {}.".format(email_address))
        return None

    # User found, check if a state already exists
    state = current_app.password_reset_state_db.get_state_by_eppn(eppn=user.eppn, raise_on_missing=False)
    if state and not state.email_code.is_expired(timeout_seconds=current_app.conf.email_code_timeout):
        # If a state is found and not expired, just send another message with the same code
        # Update created_ts to give the user another email_code_timeout seconds to complete the password reset
        state.email_code.created_ts = datetime.utcnow()
    else:
        # create a new state
        state = PasswordResetEmailState(eppn=user.eppn, email_address=email_address, email_code=get_unique_hash())
    current_app.password_reset_state_db.save(state)

    text_template = 'reset_password_email.txt.jinja2'
    html_template = 'reset_password_email.html.jinja2'
    to_addresses = [address.email for address in user.mail_addresses.verified.to_list()]

    password_reset_timeout = current_app.conf.email_code_timeout // 60 // 60  # seconds to hours
    context = {
        'reset_password_link': url_for(
            'reset_password.email_reset_code', email_code=state.email_code.code, _external=True
        ),
        'password_reset_timeout': password_reset_timeout,
    }
    subject = _('Reset password')
    send_mail(subject, to_addresses, text_template, html_template, current_app, context, state.reference)
    current_app.logger.info('Sent password reset email to user {}'.format(state.eppn))
    current_app.logger.debug('Mail address: {}'.format(to_addresses))


@deprecated("Remove once the password reset views are served from their own webapp")
def verify_email_address(state):
    """
    :param state: Password reset state
    :type state: PasswordResetEmailState
    :return: True|False
    :rtype: bool
    """

    user = current_app.central_userdb.get_user_by_eppn(state.eppn, raise_on_missing=False)
    if not user:
        current_app.logger.error('Could not find user {}'.format(state.eppn))
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
        current_app.logger.info('Email code marked as used for {}'.format(state.eppn))
        return True

    return False


@deprecated("Remove once the password reset views are served from their own webapp")
def send_verify_phone_code(state, phone_number: str):
    state = PasswordResetEmailAndPhoneState.from_email_state(
        state, phone_number=phone_number, phone_code=get_short_hash()
    )
    current_app.password_reset_state_db.save(state)

    template = 'reset_password_sms.txt.jinja2'
    context = {'verification_code': state.phone_code.code}
    send_sms(phone_number=state.phone_number, text_template=template, reference=state.reference, context=context)
    current_app.logger.info('Sent password reset sms to user {}'.format(state.eppn))
    current_app.logger.debug('Phone number: {}'.format(state.phone_number))


@deprecated("Remove once the password reset views are served from their own webapp")
def verify_phone_number(state):
    """
    :param state: Password reset state
    :type state: PasswordResetEmailAndPhoneState
    :return: True|False
    :rtype: bool
    """

    user = current_app.central_userdb.get_user_by_eppn(state.eppn, raise_on_missing=False)
    if not user:
        current_app.logger.error('Could not find user {}'.format(state.eppn))
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
        current_app.logger.info('Phone code marked as used for {}'.format(state.eppn))
        return True

    return False


@deprecated("Remove once the password reset views are served from their own webapp")
def extra_security_used(state):
    """
    Check if any extra security method was used

    :param state: Password reset state
    :type state: PasswordResetState
    :return: True|False
    :rtype: bool
    """
    if isinstance(state, PasswordResetEmailAndPhoneState):
        return state.email_code.is_verified and state.phone_code.is_verified

    return False


@deprecated("Remove once the password reset views are served from their own webapp")
def reset_user_password(state, password):
    """
    :param state: Password reset state
    :type state: PasswordResetState
    :param password: Plain text password
    :type password: six.string_types
    :return: None
    :rtype: None
    """
    vccs_url = current_app.conf.vccs_url

    user = current_app.central_userdb.get_user_by_eppn(state.eppn, raise_on_missing=False)
    security_user = SecurityUser.from_user(user, private_userdb=current_app.private_userdb)

    # If no extra security is all verified information (except email addresses) is set to not verified
    if not extra_security_used(state):
        current_app.logger.info('No extra security used by user {}'.format(state.eppn))
        # Phone numbers
        verified_phone_numbers = security_user.phone_numbers.verified.to_list()
        if verified_phone_numbers:
            current_app.logger.info('Unverifying phone numbers for user {}'.format(state.eppn))
            security_user.phone_numbers.primary.is_primary = False
            for phone_number in verified_phone_numbers:
                phone_number.is_verified = False
                current_app.logger.debug('Phone number {} unverified'.format(phone_number.number))
        # NINs
        verified_nins = security_user.nins.verified.to_list()
        if verified_nins:
            current_app.logger.info('Unverifying nins for user {}'.format(state.eppn))
            security_user.nins.primary.is_primary = False
            for nin in verified_nins:
                nin.is_verified = False
                current_app.logger.debug('NIN {} unverified'.format(nin.number))

    if not reset_password(security_user, new_password=password, application='security', vccs_url=vccs_url):
        current_app.logger.error('Failed resetting password')
        return

    security_user.terminated = False
    save_and_sync_user(security_user)
    current_app.stats.count(name='security_password_reset', value=1)
    current_app.logger.info('Reset password successful for user {}'.format(security_user.eppn))


@deprecated("Remove once the password reset views are served from their own webapp")
def get_extra_security_alternatives(eppn):
    """
    :param eppn: Users unique eppn
    :type eppn: six.string_types
    :return: Dict of alternatives
    :rtype: dict
    """
    alternatives = {}
    user = current_app.central_userdb.get_user_by_eppn(eppn, raise_on_missing=True)

    if user.phone_numbers.verified.count:
        verified_phone_numbers = [item.number for item in user.phone_numbers.verified.to_list()]
        alternatives['phone_numbers'] = verified_phone_numbers
    return alternatives


@deprecated("Remove once the password reset views are served from their own webapp")
def mask_alternatives(alternatives):
    """
    :param alternatives: Extra security alternatives collected from user
    :type alternatives: dict
    :return: Masked extra security alternatives
    :rtype: dict
    """
    if alternatives:
        # Phone numbers
        masked_phone_numbers = []
        for phone_number in alternatives.get('phone_numbers', []):
            masked_number = '{}{}'.format('X' * (len(phone_number) - 2), phone_number[len(phone_number) - 2 :])
            masked_phone_numbers.append(masked_number)

        alternatives['phone_numbers'] = masked_phone_numbers
    return alternatives


@deprecated("Remove once the password reset views are served from their own webapp")
def get_zxcvbn_terms(eppn):
    """
    :param eppn: User eppn
    :type eppn: six.string_types
    :return: List of user info
    :rtype: list

    Combine known data that is bad for a password to a list for zxcvbn.
    """
    user = current_app.central_userdb.get_user_by_eppn(eppn, raise_on_missing=True)
    user_input = list()

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
