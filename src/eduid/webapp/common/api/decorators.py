import json
import logging
from collections.abc import Awaitable, Callable, Mapping
from functools import wraps
from typing import Any, TypeVar, cast

from flask import abort, jsonify, request
from flask.typing import ResponseReturnValue as FlaskResponseReturnValue
from flask.wrappers import Response as FlaskResponse
from marshmallow import Schema
from marshmallow.exceptions import ValidationError
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.userdb import NinIdentity
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response
from eduid.webapp.common.api.schemas.models import (
    FluxFailResponse,
    FluxResponse,
    FluxResponseStatus,
    FluxSuccessResponse,
)
from eduid.webapp.common.api.utils import get_reference_nin_from_navet_data, get_user
from eduid.webapp.common.session import session
from eduid.webapp.letter_proofing.app import LetterProofingApp
from eduid.webapp.lookup_mobile_proofing.app import MobileProofingApp
from eduid.webapp.oidc_proofing.app import OIDCProofingApp

__author__ = "lundberg"

logger = logging.getLogger(__name__)
flux_logger = logger.getChild("flux")


EduidViewBackwardsCompat = Mapping[str, Any]  # TODO: Make our views stop returning dicts and remove this
EduidViewResult = FluxData | WerkzeugResponse | EduidViewBackwardsCompat
# The Flask route decorator first in the chain makes us have to accept the full ResponseReturnValue too
EduidViewReturnType = (
    EduidViewResult | FlaskResponseReturnValue | Awaitable[EduidViewResult] | Awaitable[FlaskResponseReturnValue]
)
EduidRouteCallable = Callable[..., EduidViewReturnType]


def require_eppn(f: EduidRouteCallable) -> EduidRouteCallable:
    """
    Decorator for views that require a known (but not necessarily logged in) user.

    Will put the eppn of the user (from session.common.eppn) in the kwargs dict.

    Because it can return a FluxData, this decorator must come after the MarshalWith decorator.
    """

    @wraps(f)
    def require_eppn_decorator(*args: Any, **kwargs: Any) -> EduidViewReturnType:
        eppn = session.common.eppn
        # If the user is logged in and has a session
        # pass on the request to the decorated view
        # together with the eppn of the logged-in user.
        if not eppn:
            abort(401)
        kwargs["eppn"] = eppn
        return f(*args, **kwargs)

    return require_eppn_decorator


def require_not_logged_in(f: EduidRouteCallable) -> EduidRouteCallable:
    """
    Decorator for views that require the user not to be logged in.

    Because it can return a FluxData, this decorator must come after the MarshalWith decorator.
    """

    @wraps(f)
    def require_eppn_decorator(*args: Any, **kwargs: Any) -> EduidViewReturnType:
        if session.common.is_logged_in:
            return error_response(message=CommonMsg.logout_required)
        return f(*args, **kwargs)

    return require_eppn_decorator


TRequireUserResult = TypeVar("TRequireUserResult")


def require_user(f: Callable[..., TRequireUserResult]) -> Callable[..., TRequireUserResult]:
    """
    Decorator for functions that require a *logged in* user.

    Will put the user object in the kwargs dict.

    This decorator is not only used by Flask views, so we don't put any restrictions on the return type.
    """

    @wraps(f)
    def require_user_decorator(*args: Any, **kwargs: Any) -> TRequireUserResult:
        user = get_user()
        kwargs["user"] = user
        return f(*args, **kwargs)

    return require_user_decorator


def can_verify_nin(f: EduidRouteCallable) -> EduidRouteCallable:
    """
    Decorator to perform some checks before views that can result in a verified NIN.

    Because it can return a FluxData, this decorator must come after the MarshalWith decorator.
    """

    @wraps(f)
    def verify_identity_decorator(*args: Any, **kwargs: Any) -> EduidViewReturnType:
        user = get_user()
        # A user can just have one verified NIN
        if user.identities.nin is not None and user.identities.nin.is_verified is True:
            logger.info("User already has a verified NIN")
            return error_response(message=CommonMsg.user_already_verified)
        # A user can not verify a nin if another previously was verified
        locked_nin = user.locked_identity.nin
        if isinstance(locked_nin, NinIdentity) and locked_nin.number != kwargs["nin"]:
            logger.info("User has a different locked NIN")
            logger.debug(f"Locked NIN: {locked_nin.number}. New NIN: {kwargs['nin']}")
            if isinstance(session.app, MobileProofingApp | LetterProofingApp | OIDCProofingApp):
                ref = get_reference_nin_from_navet_data(kwargs["nin"])
                logger.debug(f"New NIN has reference NIN: {ref}")
                # If the reference NIN is the same as the locked NIN, we can continue with the verification
                if locked_nin.number == ref:
                    logger.info(
                        "User has a different locked NIN but it is the same as the reference NIN for the new NIN"
                    )
                    return f(*args, **kwargs)

            return error_response(message=CommonMsg.user_has_other_locked_nin)

        return f(*args, **kwargs)

    return verify_identity_decorator


class MarshalWith:
    """
    Decorator to format the data returned from a Flask view and ensure it conforms to a marshmallow schema.

    A common usage is to use this to format the response as a Flux Standard Action
    (https://github.com/redux-utilities/flux-standard-action) by using a schema that has FluxStandardAction
    as superclass, or as a mixin.

    See the documentation of the FluxResponse class, or the link above, for more information about the
    on-the-wire format of these Flux Standard Actions.
    """

    def __init__(self, schema: type[Schema]) -> None:
        self.schema = schema

    def __call__(self, f: EduidRouteCallable) -> Callable:
        @wraps(f)
        def marshal_decorator(*args: Any, **kwargs: Any) -> WerkzeugResponse:
            # Call the Flask view, which is expected to return a FluxData instance,
            # or in special cases an WerkzeugResponse (e.g. when a redirect is performed).
            ret = f(*args, **kwargs)

            if isinstance(ret, WerkzeugResponse | FlaskResponse):
                # No need to Marshal again, someone else already did that
                return ret

            if isinstance(ret, dict):
                # TODO: Backwards compatibility mode - work on removing the need for this
                ret = FluxData(FluxResponseStatus.OK, payload=ret)

            if not isinstance(ret, FluxData):
                raise TypeError("Data returned from Flask view was not a FluxData (or WerkzeugResponse) instance")

            _flux_response: FluxResponse
            if ret.status != FluxResponseStatus.OK:
                _flux_response = FluxFailResponse(request, meta=ret.meta, payload=ret.payload)
            else:
                _flux_response = FluxSuccessResponse(request, meta=ret.meta, payload=ret.payload)
            try:
                flux_logger.debug(f"Encoding response: {_flux_response.to_dict()} using schema {self.schema()}")
                _encoded = cast(Mapping[str, Any], self.schema().dump(_flux_response.to_dict()))
                res = jsonify(_encoded)
                flux_logger.debug(f"Encoded response: {_encoded}")
            except:
                logger.exception(f"Could not serialise Flux payload:\n{_flux_response.to_dict()}")
                raise
            return res

        return marshal_decorator


class UnmarshalWith:
    """
    Decorator to validate the data sent to a Flask view and ensure it conforms to a marshmallow schema.

    Basically transforms the request data into a dict that is passed to the Flask view as keyword arguments.

    This should be the first decorator after Flask's route decorator, and must return a FlaskResponseReturnValue,
    not a FluxData instance.
    """

    def __init__(self, schema: type[Schema]) -> None:
        self.schema = schema

    def __call__(self, f: EduidRouteCallable) -> Callable:
        @wraps(f)
        def unmarshal_decorator(
            *args: Any, **kwargs: Any
        ) -> FlaskResponseReturnValue:  # DO NOT change to EduidViewReturnType, this is our outmost decorator
            flux_logger.debug("")
            flux_logger.debug(f"--- New request ({request.path})")
            # silent=True lets get_json return None even if mime-type is not application/json
            json_data: Mapping[str, Any] | None = request.get_json(silent=True)
            if json_data is None:
                json_data = {}
            _data_str = str(json_data)
            if "password" in _data_str:
                flux_logger.debug(f"Decoding request with a password in it using schema {self.schema()}")
            else:
                flux_logger.debug(f"Decoding request: {repr(json_data)} using schema {self.schema()}")
            try:
                unmarshal_result = cast(dict[str, Any], self.schema().load(json_data))
            except ValidationError as e:
                response_data = FluxFailResponse(
                    request,
                    payload={
                        "error": cast(Any, e.normalized_messages()),
                        "csrf_token": session.get_csrf_token(),
                    },
                )
                logger.warning(f"Error un-marshalling request using {self.schema}: {e.normalized_messages()}")
                if "password" in _data_str:
                    logger.debug("Failing request has a password in it, not logging JSON data")
                else:
                    logger.debug(f"Failing request JSON data:\n{json.dumps(json_data, indent=4, sort_keys=True)}")
                error_response: FlaskResponse = jsonify(response_data.to_dict())
                return error_response
            if "password" in unmarshal_result:
                # A simple safeguard for if debug logging is ever activated in production
                _without_pw = dict(unmarshal_result)
                _without_pw["password"] = "REDACTED"
                flux_logger.debug(f"Decoded request: {_without_pw}")
            else:
                flux_logger.debug(f"Decoded request: {unmarshal_result}")
            kwargs.update(unmarshal_result)
            ret = f(*args, **kwargs)
            if isinstance(ret, FluxData):
                raise TypeError("Wrong order of decorators, UnmarshalWith must be the first decorator")
            # Uh, don't know how to check for Awaitable[FluxData], so for now we just ignore the type error below
            return ret  # type: ignore

        return unmarshal_decorator
