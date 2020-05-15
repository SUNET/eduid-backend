# -*- coding: utf-8 -*-
from typing import List, Optional, Type

from flask import current_app, render_template, request

from eduid_userdb.nin import Nin
from eduid_userdb.proofing import ProofingUser
from eduid_userdb.proofing.state import NinProofingState
from eduid_userdb.user import User

from eduid_common.config.base import BaseConfig

from eduid_common.api.app import EduIDBaseApp

__author__ = 'lundberg'


def set_user_names_from_offical_address(proofing_user, proofing_log_entry):
    """
    :param proofing_user: Proofing app private userdb user
    :param proofing_log_entry: Proofing log entry element

    :type proofing_user: eduid_userdb.proofing.ProofingUser
    :type proofing_log_entry: eduid_userdb.log.element.NinProofingLogElement

    :returns: User object
    :rtype: eduid_userdb.proofing.ProofingUser
    """
    navet_data = proofing_log_entry.user_postal_address
    name = navet_data['Name']
    proofing_user.given_name = name['GivenName']
    proofing_user.surname = name['Surname']
    given_name_marking = name.get('GivenNameMarking')
    # Only set display name if not already set
    if not proofing_user.display_name:
        if given_name_marking:
            given_name_marking = int((int(given_name_marking) / 10) - 1)  # ex. "20" -> 1 (second given name)
            proofing_user.display_name = u'{} {}'.format(
                name['GivenName'].split()[given_name_marking], proofing_user.surname
            )
        else:
            proofing_user.display_name = u'{} {}'.format(proofing_user.given_name, proofing_user.surname)
    current_app.logger.info(u'User names set from official address')
    current_app.logger.debug(
        u'{} resulted in given_name: {}, surname: {} and display_name: {}'.format(
            name, proofing_user.given_name, proofing_user.surname, proofing_user.display_name
        )
    )
    return proofing_user


def number_match_proofing(user, proofing_state, number):
    """
    :param user: Central userdb user
    :param proofing_state: Proofing state for user
    :param number: National identityt number

    :type user: eduid_userdb.user.User
    :type proofing_state: eduid_userdb.proofing.OidcProofingState
    :type number: six.string_types

    :return: True|False
    :rtype: bool
    """
    if proofing_state.nin.number == number:
        return True
    current_app.logger.error('Self asserted NIN does not match for user {}'.format(user))
    current_app.logger.debug(
        'Self asserted NIN: {}. NIN from vetting provider {}'.format(proofing_state.nin.number, number)
    )
    return False


def add_nin_to_user(user: User, proofing_state: NinProofingState, user_class: Type[User] = ProofingUser) -> None:

    proofing_user = user_class.from_user(user, current_app.private_userdb)
    # Add nin to user if not already there
    if not proofing_user.nins.find(proofing_state.nin.number):
        current_app.logger.info('Adding NIN for user {}'.format(user))
        current_app.logger.debug('Self asserted NIN: {}'.format(proofing_state.nin.number))
        nin_element = Nin(
            number=proofing_state.nin.number,
            application=proofing_state.nin.created_by,
            verified=proofing_state.nin.is_verified,
            created_ts=proofing_state.nin.created_ts,
            primary=False,
        )
        proofing_user.nins.add(nin_element)
        proofing_user.modified_ts = True
        # Save user to private db
        current_app.private_userdb.save(proofing_user, check_sync=False)
        # Ask am to sync user to central db
        current_app.logger.info('Request sync for user {!s}'.format(proofing_user))
        result = current_app.am_relay.request_user_sync(proofing_user)
        current_app.logger.info('Sync result for user {!s}: {!s}'.format(proofing_user, result))


def verify_nin_for_user(user, proofing_state, proofing_log_entry):
    """
    :param user: Central userdb user
    :param proofing_state: Proofing state for user
    :param proofing_log_entry: Proofing log entry element

    :type user: eduid_userdb.user.User
    :type proofing_state: eduid_userdb.proofing.NinProofingState
    :type proofing_log_entry: eduid_userdb.log.element.ProofingLogElement

    :return: None
    """
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    nin_element = proofing_user.nins.find(proofing_state.nin.number)
    if not nin_element:
        nin_element = Nin(
            number=proofing_state.nin.number,
            application=proofing_state.nin.created_by,
            created_ts=proofing_state.nin.created_ts,
            verified=False,
            primary=False,
        )
        proofing_user.nins.add(nin_element)

    # Check if the NIN is already verified
    if nin_element and nin_element.is_verified:
        current_app.logger.info('NIN is already verified for user {}'.format(proofing_user))
        current_app.logger.debug('NIN: {}'.format(proofing_state.nin.number))
        return

    # Update users nin element
    if proofing_user.nins.primary is None:
        # No primary NIN found, make the only verified NIN primary
        nin_element.is_primary = True
    nin_element.is_verified = True
    nin_element.verified_ts = True
    nin_element.verified_by = proofing_state.nin.created_by

    # Update users name
    proofing_user = set_user_names_from_offical_address(proofing_user, proofing_log_entry)

    # If user was updated successfully continue with logging the proof and saving the user to central db
    # Send proofing data to the proofing log
    if current_app.proofing_log.save(proofing_log_entry):
        current_app.logger.info('Recorded verification for {} in the proofing log'.format(proofing_user))
        # User from central db is as up to date as it can be no need to check for modified time
        proofing_user.modified_ts = True
        # Save user to private db
        current_app.private_userdb.save(proofing_user, check_sync=False)

        # Ask am to sync user to central db
        current_app.logger.info('Request sync for user {!s}'.format(user))
        result = current_app.am_relay.request_user_sync(proofing_user)
        current_app.logger.info('Sync result for user {!s}: {!s}'.format(proofing_user, result))


def send_mail(
    subject: str,
    to_addresses: List[str],
    text_template: str,
    html_template: str,
    app: EduIDBaseApp,
    context: Optional[dict] = None,
    reference: Optional[str] = None,
):
    """
    :param subject: subject text
    :param to_addresses: email addresses for the to field
    :param text_template: text message as a jinja template
    :param html_template: html message as a jinja template
    :param app: Flask current app
    :param context: template context
    :param reference: Audit reference to help cross reference audit log and events
    """
    site_name = app.config.eduid_site_name
    site_url = app.config.eduid_site_url

    default_context = {
        "site_url": site_url,
        "site_name": site_name,
    }
    if not context:
        context = {}
    context.update(default_context)

    app.logger.debug(f'subject: {subject}')
    app.logger.debug(f'to addresses: {to_addresses}')
    text = render_template(text_template, **context)
    app.logger.debug(f'rendered text: {text}')
    html = render_template(html_template, **context)
    app.logger.debug(f'rendered html: {html}')
    app.mail_relay.sendmail(subject, to_addresses, text, html, reference)


def check_magic_cookie(config: BaseConfig) -> bool:
    """
    Check that the environment allows the use of magic_cookies, that there is a magic cookie,
    and that the content of the magic cookie coincides with the configured magic cookie.

    :param config: A configuration object
    """
    if config.environment in ('dev', 'staging') and config.magic_cookie and config.magic_cookie_name:
        cookie = request.cookies.get(config.magic_cookie_name)
        if cookie is not None:
            return cookie == config.magic_cookie

    return False
