# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import current_app, render_template, url_for
from eduid_common.api.utils import get_unique_hash
from eduid_userdb.security import PasswordResetEmailState
from eduid_userdb.exceptions import UserDoesNotExist
from eduid_webapp.security.schemas import ConvertRegisteredKeys

__author__ = 'lundberg'


def credentials_to_registered_keys(user_u2f_tokens):
    """
    :param user_u2f_tokens: List of users U2F credentials
    :type user_u2f_tokens: eduid_userdb.credentials.CredentialList

    :return: List of registered keys
    :rtype: list
    """
    u2f_dicts = user_u2f_tokens.to_list_of_dicts()
    return ConvertRegisteredKeys().dump({'registered_keys': u2f_dicts}).data['registered_keys']


def compile_credential_list(security_user):
    """
    :param security_user: User
    :type security_user: eduid_userdb.security.SecurityUser
    :return: List of augmented credentials
    :rtype: list
    """
    credentials = []
    authn_info = current_app.authninfo_db.get_authn_info(security_user)
    for credential in security_user.credentials.to_list():
        credential_dict = credential.to_dict()
        credential_dict['key'] = credential.key
        credential_dict.update(authn_info[credential.key])
        credentials.append(credential_dict)
    return credentials


def send_mail(to_addresses, text_template, html_template, context=None):
    site_name = current_app.config.get("EDUID_SITE_NAME")
    site_url = current_app.config.get("EDUID_SITE_URL")
    sender = current_app.config.get('MAIL_DEFAULT_FROM')

    default_context = {
        "site_url": site_url,
        "site_name": site_name,
    }
    if not context:
        context = {}
    context.update(default_context)

    text = render_template(text_template, **context)
    html = render_template(html_template, **context)
    current_app.mail_relay.sendmail(sender, to_addresses, text, html)


def send_termination_mail(user):
    """
    :param user: User object
    :type user: User

    Sends a termination mail to all verified mail addresses for the user.
    """
    text_template = "termination_email.txt.jinja2"
    html_template = "termination_email.html.jinja2"
    to_addresses = [address.email for address in user.mail_addresses.to_list() if address.is_verified]
    send_mail(to_addresses, text_template, html_template)
    current_app.logger.info("Sent termination email to user.")


def send_password_reset_mail(email_address):
    """
    :param email_address: User input for password reset
    :type email_address: six.string_types
    :return:
    :rtype:
    """
    user = current_app.central_userdb.get_user_by_mail(email_address, raise_on_missing=False)
    if user:
        state = PasswordResetEmailState(eppn=user.eppn, email_address=email_address, email_code=get_unique_hash())
        current_app.password_reset_state_db.save(state)
        text_template = "reset_password_email.txt.jinja2"
        html_template = "reset_password_email.html.jinja2"
        to_addresses = [address.email for address in user.mail_addresses.to_list() if address.is_verified]

        password_reset_timeout = int(current_app.config.get("EMAIL_CODE_TIMEOUT_MINUTES")) / 60
        context = {
            'reset_password_link': url_for('reset_password.email_reset_code', email_code=state.email_code.code,
                                           _external=True),
            'password_reset_timeout': password_reset_timeout
        }
        send_mail(to_addresses, text_template, html_template, context)
        current_app.logger.info("Sent password reset email to user with the following addresses: {}.".format(
            to_addresses))
    current_app.logger.info("Found no user with the following address: {}.".format(email_address))


def get_extra_security_alternatives(eppn):
    """
    :param eppn: Users unique eppn
    :type eppn: six.string_types
    :return: Dict of alternatives
    :rtype: dict
    """
    alternatives = {}
    try:
        user = current_app.central_userdb.get_user_by_eppn(eppn)
    except UserDoesNotExist as e:
        raise e
    if user:
        if user.phone_numbers.count:
            verified_phone_numbers = [item.number for item in user.phone_numbers.to_list() if item.is_verified]
            alternatives['phone_numbers'] = verified_phone_numbers
    return alternatives




