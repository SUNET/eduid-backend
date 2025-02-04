import logging
import os
import re
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, TypeVar, cast
from unittest.mock import MagicMock
from urllib.parse import urlparse
from uuid import uuid4

import bcrypt
from flask import current_app as flask_current_app
from flask.wrappers import Request

from eduid.common.config.base import EduIDBaseAppConfig, FrontendAction, Pysaml2SPConfigMixin
from eduid.common.misc.timeutil import utc_now
from eduid.common.rpc.exceptions import MsgTaskFailed, NoNavetData
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.userdb import User, UserDB
from eduid.userdb.exceptions import MultipleUsersReturned, UserDBValueError, UserDoesNotExist
from eduid.webapp.common.api.exceptions import ApiException

if TYPE_CHECKING:
    from eduid.webapp.common.api.app import EduIDBaseApp

    current_app = cast(EduIDBaseApp, flask_current_app)
else:
    current_app = flask_current_app

logger = logging.getLogger(__name__)


TCurrentAppAttribute = TypeVar("TCurrentAppAttribute")


def get_from_current_app(name: str, klass: type[TCurrentAppAttribute]) -> TCurrentAppAttribute:
    """Get a correctly typed attribute from an unknown Flask current app"""
    ret = getattr(current_app, name)
    if not isinstance(ret, klass):
        # For tests, we may have a mock object here
        conf = getattr(current_app, "conf")
        if isinstance(conf, EduIDBaseAppConfig) and conf.testing:
            if isinstance(ret, MagicMock):
                return cast(TCurrentAppAttribute, ret)
        raise TypeError(f"current_app.{name} is not of type {klass} (is {type(ret)}")
    return ret


def get_unique_hash() -> str:
    return str(uuid4())


def make_short_code(digits: int = 6) -> str:
    """Make a short decimal code, left-padded with zeros to the width specified by `digits'."""
    code = int.from_bytes(os.urandom(4), byteorder="big") % 1000000
    return str(code).zfill(digits)


def update_modified_ts(user: User) -> None:
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
        user_id = user.user_id
    except UserDBValueError:
        logger.debug(f"User {user} has no id, setting modified_ts to None")
        user.modified_ts = None
        return None

    _private_userdb = get_from_current_app("private_userdb", UserDB[User])
    private_user = _private_userdb.get_user_by_id(user_id)
    if private_user is None:
        logger.debug(f"User {user} not found in {_private_userdb}, setting modified_ts to None")
        user.modified_ts = None
        return None

    if private_user.modified_ts is None:
        private_user.modified_ts = utc_now()  # use current time
        logger.debug(f"Updating user {private_user} with new modified_ts: {private_user.modified_ts}")
        _private_userdb.save(private_user)

    user.modified_ts = private_user.modified_ts
    logger.debug(
        f"Updating {user} with modified_ts from central userdb user {private_user}: {private_user.modified_ts}"
    )


def get_user() -> User:
    """
    Get the currently logged-in user from the common eduid session.

    If no user has been identified, or the user is known but not currently logged in, require authentication.

    :return: Central userdb user
    """
    from eduid.webapp.common.session import session

    if not session.common.eppn or not session.common.is_logged_in:
        raise ApiException("Not authorized", status_code=401)
    try:
        # Get user from central database
        return current_app.central_userdb.get_user_by_eppn(session.common.eppn)

    except MultipleUsersReturned:
        logger.exception(f"Found multiple users in central database for eppn {session.common.eppn}.")
        raise ApiException("Not authorized", status_code=401)

    except UserDoesNotExist:
        logger.error(f"Could not find user {session.common.eppn} in central database.")
        raise ApiException("Not authorized", status_code=401)


def has_user_logged_in_with_mfa() -> bool:
    """
    Check if the user has logged in with MFA.
    """
    from eduid.webapp.common.session import session

    authn = session.authn.sp.get_authn_for_frontend_action(FrontendAction.LOGIN)
    user = get_user()

    if user and len(authn.credentials_used) > 1:
        return True
    return False


def save_and_sync_user(
    user: User, private_userdb: UserDB[User] | None = None, app_name_override: str | None = None
) -> bool:
    """
    Save (new) user object to the private userdb and propagate the changes to the central user db.

    May raise UserOutOfSync exception

    :param user: the modified user
    """
    if private_userdb is None:
        private_userdb = get_from_current_app("private_userdb", UserDB)
    logger.debug(f"Saving user {user} to private userdb {private_userdb} (is_in_database: {user.meta.is_in_database})")
    private_userdb.save(user)
    from eduid.common.rpc.am_relay import AmRelay

    logger.debug(f"Syncing {user} to central userdb {current_app.central_userdb}")
    return get_from_current_app("am_relay", AmRelay).request_user_sync(user, app_name_override=app_name_override)


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
        raise ValueError("No Flask url_rule present in request")
    # req.url_rule.rule is e.g. '/reset/config', but can also be '/', '/reset/' or '/verify-link/<code>'
    url_rule = req.url_rule.rule
    # Remove APPLICATION_ROOT from request url rule
    # XXX: There must be a better way to get the internal path info
    app_root = get_from_current_app("conf", EduIDBaseAppConfig).flask.application_root
    if app_root is not None and url_rule.startswith(app_root):
        url_rule = url_rule[len(app_root) :]
    # replace slashes and hyphens with spaces
    url_rule = url_rule.replace("/", " ").replace("-", " ")
    # remove any variables (enclosed in <>) from the path
    url_rule = re.sub(r"<.+?>", "", url_rule)
    # Clean up the url_rule removing what was once trailing spaces, redundant slashes between
    # variables etc. using split() and then join()
    url_rule = "_".join(url_rule.split())
    # Combine all non-empty parts, and finally uppercase the result.
    _elements = [x for x in [method, blueprint, url_rule, suffix] if x]
    flux_type = "_".join(_elements).upper()
    return flux_type


def sanitise_redirect_url(redirect_url: str | None, safe_default: str = "/") -> str:
    """
    Make sure the URL provided in relay_state is safe and does
    not provide an open redirect.

    :param redirect_url: Next url
    :param safe_default: The default if relay state is found unsafe

    :return: Safe relay state
    """
    if redirect_url is None:
        logger.debug(f"Using safe default redirect_url {safe_default} since none was provided")
        return safe_default

    logger.debug(f"Checking if redirect_url {redirect_url} is safe")
    url_scheme = get_from_current_app("conf", EduIDBaseAppConfig).flask.preferred_url_scheme
    safe_domain = get_from_current_app("conf", Pysaml2SPConfigMixin).safe_relay_domain
    parsed_relay_state = urlparse(redirect_url)

    # If relay state is only a path
    if (not parsed_relay_state.scheme and not parsed_relay_state.netloc) and parsed_relay_state.path:
        logger.debug(f"redirect_url {redirect_url} with only a path is considered safe")
        return redirect_url

    # If schema matches PREFERRED_URL_SCHEME and fqdn ends with dot SAFE_RELAY_DOMAIN or equals SAFE_RELAY_DOMAIN
    if parsed_relay_state.scheme == url_scheme:
        if parsed_relay_state.netloc.endswith("." + safe_domain) or parsed_relay_state.netloc == safe_domain:
            logger.debug(f'redirect_url {redirect_url} to safe_domain "{safe_domain}" is considered safe')
            return redirect_url

    # Unsafe redirect_url found
    logger.warning(f"Caught unsafe redirect_url: {redirect_url}. Using safe default: {safe_default}.")
    return safe_default


def hash_password(password: str) -> str:
    """
    Return a hash of the provided password

    :param password: password as plaintext
    """
    password = "".join(password.split())
    ret: Any = bcrypt.hashpw(password, bcrypt.gensalt())
    if not isinstance(ret, str):
        raise TypeError("bcrypt.hashpw returned a non-string value")
    return ret


def check_password_hash(password: str, hashed: str | None) -> bool:
    """
    Check that the provided password corresponds to the provided hash
    """
    if hashed is None:
        return False
    password = "".join(password.split())
    ret: Any = bcrypt.checkpw(password, hashed)
    if not isinstance(ret, bool):
        raise TypeError(f"bcrypt.checkpw returned {ret} which is not a bool")
    return ret


def get_zxcvbn_terms(user: User) -> list[str]:
    """
    Combine known data that is bad for a password to a list for zxcvbn.

    :param user: User
    :return: List of user info
    """
    user_input: list[str] = []
    # Personal info
    if user.given_name:
        user_input.append(user.given_name)
    if user.surname:
        user_input.append(user.surname)

    # Mail addresses
    if user.mail_addresses.count:
        user_input.extend(item.email.split("@")[0] for item in user.mail_addresses.to_list())

    return user_input


def time_left(ts: datetime, delta: timedelta) -> timedelta:
    end_time = ts + delta
    _time_left = end_time - utc_now()
    if _time_left.total_seconds() <= 0:
        return timedelta()
    return _time_left


def is_throttled(ts: datetime, min_wait: timedelta) -> bool:
    throttle_time_left = time_left(ts=ts, delta=min_wait)
    if int(throttle_time_left.total_seconds()) > 0:
        logger.info(f"Resend throttled for {throttle_time_left}")
        return True
    return False


def is_expired(ts: datetime, max_age: timedelta) -> bool:
    return utc_now() - ts > max_age


def get_reference_nin_from_navet_data(nin: str) -> str | None:
    """
    Check if the NIN has changed in Navet data.
    """
    try:
        msg_relay = get_from_current_app("msg_relay", MsgRelay)
    except AttributeError:
        # If for some reason the msg_relay is not in the current app, return None.
        # This should not happen, but if it does, we don't want to crash the service.
        # Instead, we log the error and return None.
        logger.error("Could not get msg_relay from current app")
        return None

    try:
        navet_data = msg_relay.get_all_navet_data(nin=nin)
        if navet_data.person.reference_national_identity_number:
            return navet_data.person.reference_national_identity_number
    except NoNavetData:
        pass  # all persons with a NIN is not in Navet
    except MsgTaskFailed:
        # the verification will probably fail anyway, but we don't want to be
        # dependent on Navet for verifications any longer
        logger.exception("No connection to Navet")

    return None
