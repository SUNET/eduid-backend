# -*- coding: utf-8 -*-

import re
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse
from uuid import uuid4

from flask import Request, current_app

from eduid.userdb import User, UserDB
from eduid.userdb.exceptions import EduIDUserDBError, MultipleUsersReturned, UserDBValueError, UserDoesNotExist
from eduid.webapp.common.api.exceptions import ApiException


def get_unique_hash() -> str:
    return str(uuid4())


def get_short_hash(entropy=10) -> str:
    return uuid4().hex[:entropy]


def update_modified_ts(user):
    """
    When loading a user from the central userdb, the modified_ts has to be
    loaded from the private userdb (since it is not propagated to 'attributes'
    by the eduid-am worker).

    This need should go away once there is a global version number on the user document.

    :param user: User object from the central userdb
    :type user: eduid.userdb.User

    :return: None
    """
    try:
        userid = user.user_id
    except UserDBValueError:
        current_app.logger.debug("User {!s} has no id, setting modified_ts to None".format(user))
        user.modified_ts = None
        return

    private_user = current_app.private_userdb.get_user_by_id(userid, raise_on_missing=False)
    if private_user is None:
        current_app.logger.debug(
            "User {!s} not found in {!s}, " "setting modified_ts to None".format(user, current_app.private_userdb)
        )
        user.modified_ts = None
        return

    if private_user.modified_ts is None:
        private_user.modified_ts = datetime.utcnow()  # use current time
        current_app.logger.debug(
            "Updating user {!s} with new modified_ts: {!s}".format(private_user, private_user.modified_ts)
        )
        current_app.private_userdb.save(private_user, check_sync=False)

    user.modified_ts = private_user.modified_ts
    current_app.logger.debug(
        "Updating {!s} with modified_ts from central userdb user {!s}: {!s}".format(
            user, private_user, private_user.modified_ts
        )
    )


def get_user() -> User:
    """
    Get the currently logged in user from the common eduid session.

    If no user has been identified, or the user is known but not currently logged in, require authentication.

    :return: Central userdb user
    """
    from eduid.webapp.common.session import session

    if not session.common.eppn or not session.common.is_logged_in:
        raise ApiException('Not authorized', status_code=401)
    try:
        # Get user from central database
        return current_app.central_userdb.get_user_by_eppn(session.common.eppn, raise_on_missing=True)
    except UserDoesNotExist as e:
        current_app.logger.error('Could not find user in central database.')
        current_app.logger.error(e)
        raise ApiException('Not authorized', status_code=401)
    except MultipleUsersReturned as e:
        current_app.logger.error('Found multiple users in central database.')
        current_app.logger.error(e)
        raise ApiException('Not authorized', status_code=401)


def save_and_sync_user(
    user: User, private_userdb: Optional[UserDB] = None, app_name_override: Optional[str] = None
) -> bool:
    """
    Save (new) user object to the private userdb and propagate the changes to the central user db.

    May raise UserOutOfSync exception

    :param user: the modified user
    :type user: current_app.private_userdb.UserClass
    """
    if private_userdb is None:
        private_userdb = current_app.private_userdb
    if not isinstance(user, private_userdb.UserClass):
        raise EduIDUserDBError(f'user is not of type {private_userdb.UserClass}')
    private_userdb.save(user)
    return current_app.am_relay.request_user_sync(user, app_name_override=app_name_override)


def urlappend(base: str, path: str) -> str:
    """
    :param base: Base url
    :param path: Path to join to base
    :return: Joined url

    Used instead of urlparse.urljoin to append path to base in an obvious way.

    >>> urlappend('https://test.com/base-path', 'my-path')
    'https://test.com/base-path/my-path'
    >>> urlappend('https://test.com/base-path/', 'my-path')
    'https://test.com/base-path/my-path'
    >>> urlappend('https://test.com/base-path/', '/my-path')
    'https://test.com/base-path/my-path'
    >>> urlappend('https://test.com/base-path', '/my-path')
    'https://test.com/base-path/my-path'
    >>> urlappend('https://test.com/base-path', '/my-path/')
    'https://test.com/base-path/my-path/'
    """
    path = path.lstrip('/')
    if not base.endswith('/'):
        base = '{!s}/'.format(base)
    return '{!s}{!s}'.format(base, path)


def get_flux_type(req: Request, suffix: str) -> str:
    """
    Construct the Flux Standard Action 'type' element.

    This can be thought of as a routing information for data produced in a backend endpoint
    into the right place in the frontend. The result of this function is a string like

      POST_RESET_PASSWORD_RESET_CONFIG_SUCCESS

    and the frontend will have sort of an 'on receive' event handler, that updates the right
    parts of the frontend when data tagged with this 'type' is received.

    This string might look a bit wonky, so let's break it down. We have

      method = POST
      blueprint = RESET_PASSWORD
      url_rule = RESET_CONFIG (from the route '/config' and the blueprint url_prefix '/reset')
      suffix = SUCCESS

    We need to create a 'type' that allows the frontend to understand exactly what endpoint
    produced a response.

    It is not clear (to me, ft@) that
      - the method needs to be present
      - the blueprint is needed in addition to the url_rule
      - the suffix is needed since the Flux Standard Action will have error=True on errors

    but this is how it is currently defined and to change it requires a lot of coordination with eduid-frontend.

    :param req: flask request
    :param suffix: SUCCESS|FAIL|?
    :return: Flux Standard Action 'type' value
    """
    method = req.method
    blueprint = req.blueprint
    if req.url_rule is None:
        # mainly please mypy - but this can also happen when testing if a view doesn't have proper routing set up
        raise ValueError('No Flask url_rule present in request')
    # req.url_rule.rule is e.g. '/reset/config', but can also be '/', '/reset/' or '/verify-link/<code>'
    url_rule = req.url_rule.rule
    # Remove APPLICATION_ROOT from request url rule
    # XXX: There must be a better way to get the internal path info
    app_root = current_app.config['APPLICATION_ROOT']
    if app_root is not None and url_rule.startswith(app_root):
        url_rule = url_rule[len(app_root) :]
    # replace slashes and hyphens with spaces
    url_rule = url_rule.replace('/', ' ').replace('-', ' ')
    # remove any variables (enclosed in <>) from the path
    url_rule = re.sub(r'<.+?>', '', url_rule)
    # Clean up the url_rule removing what was once trailing spaces, redundant slashes between
    # variables etc. using split() and then join()
    url_rule = '_'.join(url_rule.split())
    # Combine all non-empty parts, and finally uppercase the result.
    _elements = [x for x in [method, blueprint, url_rule, suffix] if x]
    flux_type = '_'.join(_elements).upper()
    return flux_type


def get_static_url_for(f: str, version: Optional[str] = None) -> str:
    """
    Get the static url for a file and optionally have a version argument appended for cache busting.
    """
    static_url = current_app.conf.eduid_static_url
    if version is not None:
        static_url = urlappend(current_app.conf.eduid_static_url, version)
    return urlappend(static_url, f)


def init_template_functions(app):
    @app.template_global()
    def static_url_for(f: str, version: Optional[str] = None) -> str:
        return get_static_url_for(f, version)

    return app


def verify_relay_state(
    relay_state: str,
    safe_default: str = '/',
    logger=None,
    url_scheme: Optional[str] = None,
    safe_domain: Optional[str] = None,
) -> str:
    """
    Make sure the URL provided in relay_state is safe and does
    not provide an open redirect.

    The reason for the `logger`, `url_scheme`, and `safe_domain`
    kwargs (rather than directly taking them from the current app and config)
    is so that this can be used in non-flask apps (specifically, in the
    IdP cherrypy app). Used within a flask app, these args can be ignored.

    :param relay_state: Next url
    :param safe_default: The default if relay state is found unsafe
    :param logger: A logger facility
    :param url_scheme: the preferred URL scheme (http|https)
    :param safe_domain: Safe domain to relay

    :return: Safe relay state
    """
    if relay_state is None:
        return safe_default

    if logger is None:
        logger = current_app.logger
    logger.debug(f'Checking if relay state {relay_state} is safe')
    if url_scheme is None:
        url_scheme = current_app.config['PREFERRED_URL_SCHEME']
    if safe_domain is None:
        safe_domain = current_app.conf.safe_relay_domain
    parsed_relay_state = urlparse(relay_state)

    # If relay state is only a path
    if (not parsed_relay_state.scheme and not parsed_relay_state.netloc) and parsed_relay_state.path:
        return relay_state

    # If schema matches PREFERRED_URL_SCHEME and fqdn ends with dot SAFE_RELAY_DOMAIN or equals SAFE_RELAY_DOMAIN
    if parsed_relay_state.scheme == url_scheme:
        if parsed_relay_state.netloc.endswith('.' + safe_domain) or parsed_relay_state.netloc == safe_domain:
            return relay_state

    # Unsafe relay state found
    logger.warning(f'Caught unsafe relay state: {relay_state}. Using safe default: {safe_default}.')
    return safe_default
