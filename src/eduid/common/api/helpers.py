# -*- coding: utf-8 -*-
import warnings
from datetime import datetime
from typing import List, Optional, Type, Union

from flask import current_app, render_template, request

from eduid.userdb.logs.element import ProofingLogElement
from eduid.userdb.nin import Nin
from eduid.userdb.proofing import ProofingUser
from eduid.userdb.proofing.state import NinProofingState
from eduid.userdb.user import User

from eduid.common.api.app import EduIDBaseApp
from eduid.common.config.base import MagicCookieMixin

__author__ = 'lundberg'


def set_user_names_from_offical_address(proofing_user, proofing_log_entry):
    """
    :param proofing_user: Proofing app private userdb user
    :param proofing_log_entry: Proofing log entry element

    :type proofing_user: eduid.userdb.proofing.ProofingUser
    :type proofing_log_entry: eduid.userdb.log.element.NinProofingLogElement

    :returns: User object
    :rtype: eduid.userdb.proofing.ProofingUser
    """
    navet_data = proofing_log_entry.user_postal_address
    name = navet_data['Name']
    proofing_user.given_name = name['GivenName']
    proofing_user.surname = name['Surname']
    given_name_marking = name.get('GivenNameMarking')
    # Only set display name if not already set
    if not proofing_user.display_name:
        proofing_user.display_name = f'{proofing_user.given_name} {proofing_user.surname}'
        if given_name_marking:
            _name_index = (int(given_name_marking) // 10) - 1  # ex. "20" -> 1 (second GivenName is real given name)
            try:
                _given_name = name['GivenName'].split()[_name_index]
                proofing_user.display_name = f'{_given_name} {proofing_user.surname}'
            except IndexError:
                # At least occasionally, we've seen GivenName 'Jan-Erik Martin' with GivenNameMarking 30
                pass
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

    :type user: eduid.userdb.user.User
    :type proofing_state: eduid.userdb.proofing.OidcProofingState
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
        nin_element = Nin.from_dict(
            dict(
                number=proofing_state.nin.number,
                created_by=proofing_state.nin.created_by,
                verified=proofing_state.nin.is_verified,
                created_ts=proofing_state.nin.created_ts,
                primary=False,
            )
        )
        proofing_user.nins.add(nin_element)
        proofing_user.modified_ts = datetime.utcnow()
        # Save user to private db
        current_app.private_userdb.save(proofing_user, check_sync=False)
        # Ask am to sync user to central db
        current_app.logger.info('Request sync for user {!s}'.format(proofing_user))
        result = current_app.am_relay.request_user_sync(proofing_user)
        current_app.logger.info('Sync result for user {!s}: {!s}'.format(proofing_user, result))


def verify_nin_for_user(
    user: Union[User, ProofingUser], proofing_state: NinProofingState, proofing_log_entry: ProofingLogElement
) -> bool:
    """
    Mark a nin on a user as verified, after logging data about the proofing to the proofing log.

    If this function is given a ProofingUser instance, the instance will be updated accordingly and
    the calling function won't need to reload the user from the central database to access the updated
    NIN element.

    :param user: A ProofingUser, or a standard User
    :param proofing_state: Proofing state for user
    :param proofing_log_entry: Proofing log entry element

    :return: Success or not
    """
    if isinstance(user, ProofingUser):
        proofing_user = user
    else:
        # If user is not a ProofingUser, we create a new ProofingUser instance.
        # This is deprecated usage, since it won't allow the calling function to get
        # the new NIN element without re-loading the user from the central database.
        warnings.warn('verify_nin_for_user() called with a User, not a ProofingUser', DeprecationWarning)
        proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    nin_element = proofing_user.nins.find(proofing_state.nin.number)
    if not nin_element:
        nin_element = Nin.from_dict(
            dict(
                number=proofing_state.nin.number,
                created_by=proofing_state.nin.created_by,
                created_ts=proofing_state.nin.created_ts,
                verified=False,
                primary=False,
            )
        )
        proofing_user.nins.add(nin_element)

    # Check if the NIN is already verified
    if nin_element and nin_element.is_verified:
        current_app.logger.info('NIN is already verified for user {}'.format(proofing_user))
        current_app.logger.debug('NIN: {}'.format(proofing_state.nin.number))
        return True

    # Update users nin element
    if proofing_user.nins.primary is None:
        # No primary NIN found, make the only verified NIN primary
        nin_element.is_primary = True
    nin_element.is_verified = True
    # Ensure matching timestamp in verification log entry, and NIN element on user
    nin_element.verified_ts = proofing_log_entry.created_ts
    nin_element.verified_by = proofing_state.nin.created_by

    # Update users name
    proofing_user = set_user_names_from_offical_address(proofing_user, proofing_log_entry)

    # If user was updated successfully continue with logging the proof and saving the user to central db
    # Send proofing data to the proofing log
    if not current_app.proofing_log.save(proofing_log_entry):
        return False

    current_app.logger.info('Recorded verification for {} in the proofing log'.format(proofing_user))

    # Save user to private db
    current_app.private_userdb.save(proofing_user)

    # Ask am to sync user to central db
    current_app.logger.info('Request sync for user {!s}'.format(user))
    result = current_app.am_relay.request_user_sync(proofing_user)
    current_app.logger.info('Sync result for user {!s}: {!s}'.format(proofing_user, result))

    return True


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
    site_name = app.conf.eduid_site_name  # type: ignore
    site_url = app.conf.eduid_site_url  # type: ignore

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


def check_magic_cookie(config: MagicCookieMixin) -> bool:
    """
    This is for use in backdoor views, to check whether the backdoor is open.

    This checks that the environment allows the use of magic_cookies, that there is a magic cookie,
    and that the content of the magic cookie coincides with the configured magic cookie.

    :param config: A configuration object
    """
    if config.environment in ('dev', 'staging') and config.magic_cookie and config.magic_cookie_name:
        cookie = request.cookies.get(config.magic_cookie_name)
        if cookie is not None:
            return cookie == config.magic_cookie

    return False
