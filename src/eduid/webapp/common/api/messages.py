from collections.abc import Mapping
from copy import copy
from dataclasses import asdict, dataclass
from enum import Enum, unique
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from flask import redirect
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.config.base import FrontendAction
from eduid.webapp.common.api.schemas.authn_status import AuthnActionStatus
from eduid.webapp.common.api.schemas.models import FluxResponseStatus


@unique
class TranslatableMsg(Enum):
    """
    Subclasses of this are used to keep messages sent to the front end
    with information on the results of the attempted operations on the back end.

    Note that we cannot use this to keep common messages,
    since Python enums cannot inherit members.
    """


@unique
class CommonMsg(TranslatableMsg):
    """
    Messages sent to the front by more than one webapp.
    """

    # some form has failed to validate
    form_errors = "form-errors"
    # problem synchronising the account to the central db
    temp_problem = "Temporary technical problems"
    # The user has changed in the db since it was retrieved
    out_of_sync = "user-out-of-sync"
    # error in the communications with Navet
    navet_error = "error_navet_task"
    # no official address returned from Navet
    no_navet_data = "no_navet_data"
    # NIN validation error
    nin_invalid = "nin needs to be formatted as 18|19|20yymmddxxxx"
    # Email address validation error
    email_invalid = "email needs to be formatted according to RFC2822"
    # user must log out
    logout_required = "logout_required"
    # TODO: These _should_ be unused now - check and remove
    csrf_try_again = "csrf.try_again"
    csrf_missing = "csrf.missing"
    user_already_verified = "User is already verified"
    user_has_other_locked_nin = "Another nin is already registered for this user"
    locked_identity_not_matching = "common.locked_identity_not_matching"


@unique
class AuthnStatusMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # Status requested for unknown authn_id
    not_found = "authn_status.not-found"
    must_authenticate = "authn_status.must-authenticate"


@dataclass(frozen=True)
class FluxData:
    status: FluxResponseStatus
    payload: Mapping[str, Any]
    meta: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def success_response(
    payload: Mapping[str, Any] | None = None, message: TranslatableMsg | str | None = None
) -> FluxData:
    """
    Make a success response, that can be marshalled into a response that eduid-front understands.

    See the documentation of the MarshalWith decorator for further details on the actual on-the-wire format.

    :param payload: A mapping that will become the Flux Standard Action 'payload'.
                    This should contain data the frontend needs to render a view to the user.
                    For example, in a letter proofing scenario where a user requests that
                    a letter with a code is  sent to their registered address, the backend might
                    return the timestamp when a letter was sent, as well as when the code will
                    expire.
    :param message: An optional simple message that will be translated in eduid-front into a message to the user.
                    If used, this should be an TranslatableMsg instance or, for B/C and robustness, a str.
    """
    return FluxData(status=FluxResponseStatus.OK, payload=_make_payload(payload, message, True))


def error_response(payload: Mapping[str, Any] | None = None, message: TranslatableMsg | str | None = None) -> FluxData:
    """
    Make an error response, that can be marshalled into a response that eduid-front understands.

    See the documentation of the MarshalWith decorator for further details on the actual on-the-wire format.

    :param payload: A mapping that will become the Flux Standard Action 'payload'.
                    This should contain data the frontend needs to render a view to the user.
    :param message: An optional simple message that will be translated in eduid-front into a message to the user.
                    If used, this should be an TranslatableMsg instance or, for B/C and robustness, a str.
    """
    return FluxData(status=FluxResponseStatus.ERROR, payload=_make_payload(payload, message, False))


def need_authentication_response(
    frontend_action: FrontendAction, authn_status: AuthnActionStatus, payload: Mapping[str, Any] | None = None
) -> FluxData:
    meta = {
        "frontend_action": frontend_action.value,
        "authn_status": authn_status.value,
    }
    return FluxData(
        status=FluxResponseStatus.ERROR,
        meta=meta,
        payload=_make_payload(payload, AuthnStatusMsg.must_authenticate, success=False),
    )


def _make_payload(
    payload: Mapping[str, Any] | None, message: TranslatableMsg | str | None, success: bool
) -> Mapping[str, Any]:
    res: dict[str, Any] = {}
    if payload is not None:
        res = copy(dict(payload))  # to not mess with callers data

    if message is not None:
        if isinstance(message, TranslatableMsg):
            res["message"] = str(message.value)
        elif isinstance(message, str):
            res["message"] = message
        else:
            raise TypeError("Flux message was neither a TranslatableMsg nor a string")

    # TODO: See if the frontend actually uses this element, and if not - remove it (breaks some tests)
    if "success" not in res:
        res["success"] = success

    return res


def make_query_string(msg: TranslatableMsg, error: bool = True) -> str:
    """
    Make a query string to send a translatable message to the front in the URL of a GET request.

    :param msg: the message to send
    :param error: whether the message is an error message or a success message
    """
    msg_str = str(msg.value)
    if error:
        msg_str = ":ERROR:" + msg_str
    return urlencode({"msg": msg_str})


def redirect_with_msg(url: str, msg: TranslatableMsg | str, error: bool = True) -> WerkzeugResponse:
    """
    :param url: URL to redirect to
    :param msg: message to append to query string
    :param error: Whether it is an error message or not
    :return: Redirect response with appended query string message
    """
    if isinstance(msg, TranslatableMsg):
        msg = str(msg.value)
    if error:
        msg = ":ERROR:" + msg
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    query_list = parse_qsl(query_string)
    query_list.append(("msg", msg))
    new_query_string = urlencode(query_list)
    return redirect(urlunsplit((scheme, netloc, path, new_query_string, fragment)))
