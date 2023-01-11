#
# Copyright (c) 2020 SUNET
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
from copy import copy
from dataclasses import dataclass
from enum import Enum, unique
from typing import Any, Dict, Optional, Union
from collections.abc import Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from flask import redirect
from werkzeug.wrappers import Response as WerkzeugResponse

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
    # TODO: These _should_ be unused now - check and remove
    csrf_try_again = "csrf.try_again"
    csrf_missing = "csrf.missing"
    user_already_verified = "User is already verified"
    user_has_other_locked_nin = "Another nin is already registered for this user"
    locked_identity_not_matching = "common.locked_identity_not_matching"


@dataclass(frozen=True)
class FluxData:
    status: FluxResponseStatus
    payload: Mapping[str, Any]


def success_response(
    payload: Optional[Mapping[str, Any]] = None, message: Optional[Union[TranslatableMsg, str]] = None
) -> FluxData:
    """
    Make a success response, that can be marshalled into a response that eduid-front understands.

    See the documentation of the MarshalWith decorator for further details on the actual on-the-wire format.

    :param payload: A mapping that will become the Flux Standard Action 'payload'.
                    This should contain data the frontend needs to render a view to the user.
                    For example, in a letter proofing scenario where a user requests that
                    a letter with a code is sent to their registered address, the backend might
                    return the timestamp when a letter was sent, as well as when the code will
                    expire.
    :param message: An optional simple message that will be translated in eduid-front into a message to the user.
                    If used, this should be an TranslatableMsg instance or, for B/C and robustness, a str.
    """
    return FluxData(status=FluxResponseStatus.OK, payload=_make_payload(payload, message, True))


def error_response(
    payload: Optional[Mapping[str, Any]] = None, message: Optional[Union[TranslatableMsg, str]] = None
) -> FluxData:
    """
    Make an error response, that can be marshalled into a response that eduid-front understands.

    See the documentation of the MarshalWith decorator for further details on the actual on-the-wire format.

    :param payload: A mapping that will become the Flux Standard Action 'payload'.
                    This should contain data the frontend needs to render a view to the user.
    :param message: An optional simple message that will be translated in eduid-front into a message to the user.
                    If used, this should be an TranslatableMsg instance or, for B/C and robustness, a str.
    """
    return FluxData(status=FluxResponseStatus.ERROR, payload=_make_payload(payload, message, False))


def _make_payload(
    payload: Optional[Mapping[str, Any]], message: Optional[Union[TranslatableMsg, str]], success: bool
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


def make_query_string(msg: TranslatableMsg, error: bool = True):
    """
    Make a query string to send a translatable message to the front in the URL of a GET request.

    :param msg: the message to send
    :param error: whether the message is an error message or a success message
    """
    msg_str = str(msg.value)
    if error:
        msg_str = ":ERROR:" + msg_str
    return urlencode({"msg": msg_str})


def redirect_with_msg(url: str, msg: Union[TranslatableMsg, str], error: bool = True) -> WerkzeugResponse:
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
