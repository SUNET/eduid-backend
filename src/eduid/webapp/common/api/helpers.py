# -*- coding: utf-8 -*-
import warnings
from typing import List, Optional, Type, TypeVar, Union, overload

from flask import current_app, render_template, request

from eduid.common.config.base import MagicCookieMixin
from eduid.common.misc.timeutil import utc_now
from eduid.userdb.logs.element import NinProofingLogElement, TNinProofingLogElementSubclass
from eduid.userdb.nin import Nin
from eduid.userdb.proofing import ProofingUser
from eduid.userdb.proofing.state import NinProofingState, OidcProofingState
from eduid.userdb.user import TUserSubclass, User
from eduid.webapp.common.api.app import EduIDBaseApp

__author__ = 'lundberg'


def set_user_names_from_official_address(
    user: TUserSubclass, proofing_log_entry: TNinProofingLogElementSubclass
) -> TUserSubclass:
    """
    :param user: Proofing app private userdb user
    :param proofing_log_entry: Proofing log entry element

    :returns: User object
    """
    navet_data = proofing_log_entry.user_postal_address
    name = navet_data['Name']
    user.given_name = name['GivenName']
    user.surname = name['Surname']
    given_name_marking = name.get('GivenNameMarking')
    # Only set display name if not already set
    if not user.display_name:
        user.display_name = f'{user.given_name} {user.surname}'
        if given_name_marking:
            _name_index = (int(given_name_marking) // 10) - 1  # ex. "20" -> 1 (second GivenName is real given name)
            try:
                _given_name = name['GivenName'].split()[_name_index]
                user.display_name = f'{_given_name} {user.surname}'
            except IndexError:
                # At least occasionally, we've seen GivenName 'Jan-Erik Martin' with GivenNameMarking 30
                pass
    current_app.logger.info(u'User names set from official address')
    current_app.logger.debug(
        f'{name} resulted in given_name: {user.given_name}, surname: {user.surname} '
        f'and display_name: {user.display_name}'
    )
    return user


def number_match_proofing(user: User, proofing_state: OidcProofingState, number: str) -> bool:
    """
    :param user: Central userdb user
    :param proofing_state: Proofing state for user
    :param number: National identity number

    :return: True|False
    """
    if proofing_state.nin.number == number:
        return True
    current_app.logger.error(f'Self asserted NIN does not match for user {user}')
    current_app.logger.debug(f'Self asserted NIN: {proofing_state.nin.number}. NIN from vetting provider {number}')
    return False


# Explain to mypy that if you call add_nin_to_user without a user_type, the return type will be ProofingUser
# but if you call it with a user_type the return type will be that type
TProofingUser = TypeVar('TProofingUser', bound=User)


@overload
def add_nin_to_user(user: User, proofing_state: NinProofingState) -> ProofingUser:
    ...


@overload
def add_nin_to_user(user: User, proofing_state: NinProofingState, user_type: Type[TProofingUser]) -> TProofingUser:
    ...


def add_nin_to_user(user, proofing_state, user_type=ProofingUser):

    proofing_user = user_type.from_user(user, current_app.private_userdb)
    # Add nin to user if not already there
    if not proofing_user.nins.find(proofing_state.nin.number):
        current_app.logger.info(f'Adding NIN for user {user}')
        current_app.logger.debug(f'Self asserted NIN: {proofing_state.nin.number}')
        nin_element = Nin(
            created_by=proofing_state.nin.created_by,
            created_ts=proofing_state.nin.created_ts,
            is_primary=False,
            is_verified=proofing_state.nin.is_verified,
            number=proofing_state.nin.number,
        )
        proofing_user.nins.add(nin_element)
        proofing_user.modified_ts = utc_now()
        # Save user to private db
        current_app.private_userdb.save(proofing_user, check_sync=False)
        # Ask am to sync user to central db
        current_app.logger.info(f'Request sync for user {proofing_user}')
        result = current_app.am_relay.request_user_sync(proofing_user)
        current_app.logger.info(f'Sync result for user {proofing_user}: {result}')
    return proofing_user


def verify_nin_for_user(
    user: Union[User, ProofingUser], proofing_state: NinProofingState, proofing_log_entry: NinProofingLogElement
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
        nin_element = Nin(
            number=proofing_state.nin.number,
            created_by=proofing_state.nin.created_by,
            created_ts=proofing_state.nin.created_ts,
            is_verified=False,
            is_primary=False,
        )
        proofing_user.nins.add(nin_element)
        # What is added to the list of nins is a copy of the element, so in order
        # to continue updating it below we have to fetch it from the list again.
        nin_element = proofing_user.nins.find(nin_element.key)
        assert nin_element  # please mypy

    # Check if the NIN is already verified
    if nin_element and nin_element.is_verified:
        current_app.logger.info(f'NIN is already verified for user {proofing_user}')
        current_app.logger.debug(f'NIN: {proofing_state.nin.number}')
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
    proofing_user = set_user_names_from_official_address(proofing_user, proofing_log_entry)

    # If user was updated successfully continue with logging the proof and saving the user to central db
    # Send proofing data to the proofing log
    if not current_app.proofing_log.save(proofing_log_entry):
        return False

    current_app.logger.info(f'Recorded verification for {proofing_user} in the proofing log')

    # Save user to private db
    current_app.private_userdb.save(proofing_user)

    # Ask am to sync user to central db
    current_app.logger.info(f'Request sync for user {user}')
    result = current_app.am_relay.request_user_sync(proofing_user)
    current_app.logger.info(f'Sync result for user {proofing_user}: {result}')

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
    if config.environment not in ('dev', 'staging'):
        current_app.logger.error(f'Magic cookie not allowed in environment {config.environment}')
        return False

    if not config.magic_cookie or not config.magic_cookie_name:
        current_app.logger.error(f'Magic cookie parameters not present in configuration for {config.environment}')
        return False

    cookie = request.cookies.get(config.magic_cookie_name)
    if cookie is None:
        current_app.logger.info(f'Got no magic cookie (named {config.magic_cookie_name})')
        return False

    if cookie == config.magic_cookie:
        current_app.logger.info('check_magic_cookie check success')
        return True

    current_app.logger.info('check_magic_cookie check fail')
    return False
