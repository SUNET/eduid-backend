import json
import logging
from functools import wraps

from flask import abort, jsonify, request
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
from eduid.webapp.common.api.utils import get_user
from eduid.webapp.common.session import session

__author__ = "lundberg"

logger = logging.getLogger(__name__)
flux_logger = logger.getChild("flux")


def require_eppn(f):
    @wraps(f)
    def require_eppn_decorator(*args, **kwargs):
        eppn = session.common.eppn
        # If the user is logged in and has a session
        # pass on the request to the decorated view
        # together with the eppn of the logged-in user.
        if eppn:
            kwargs["eppn"] = eppn
            return f(*args, **kwargs)
        abort(401)

    return require_eppn_decorator


def require_user(f):
    @wraps(f)
    def require_user_decorator(*args, **kwargs):
        user = get_user()
        kwargs["user"] = user
        return f(*args, **kwargs)

    return require_user_decorator


def can_verify_nin(f):
    @wraps(f)
    def verify_identity_decorator(*args, **kwargs):
        user = get_user()
        # A user can just have one verified NIN
        if user.identities.nin is not None and user.identities.nin.is_verified is True:
            return error_response(message=CommonMsg.user_already_verified)
        # A user can not verify a nin if another previously was verified
        locked_nin = user.locked_identity.nin
        if isinstance(locked_nin, NinIdentity) and locked_nin.number != kwargs["nin"]:
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

    def __init__(self, schema):
        self.schema = schema

    def __call__(self, f):
        @wraps(f)
        def marshal_decorator(*args, **kwargs):
            # Call the Flask view, which is expected to return a FluxData instance,
            # or in special cases an WerkzeugResponse (e.g. when a redirect is performed).
            ret = f(*args, **kwargs)

            if isinstance(ret, WerkzeugResponse):
                # No need to Marshal again, someone else already did that
                return ret

            if isinstance(ret, dict):
                # TODO: Backwards compatibility mode - work on removing the need for this
                ret = FluxData(FluxResponseStatus.OK, payload=ret)

            if not isinstance(ret, FluxData):
                raise TypeError("Data returned from Flask view was not a FluxData (or WerkzeugResponse) instance")

            _flux_response: FluxResponse
            if ret.status != FluxResponseStatus.OK:
                _flux_response = FluxFailResponse(request, payload=ret.payload)
            else:
                _flux_response = FluxSuccessResponse(request, payload=ret.payload)
            try:
                flux_logger.debug(f"Encoding response: {_flux_response.to_dict()} using schema {self.schema()}")
                _encoded = self.schema().dump(_flux_response.to_dict())
                res = jsonify(_encoded)
                flux_logger.debug(f"Encoded response: {_encoded}")
            except:
                logger.exception(f"Could not serialise Flux payload:\n{_flux_response.to_dict()}")
                raise
            return res

        return marshal_decorator


class UnmarshalWith:
    def __init__(self, schema):
        self.schema = schema

    def __call__(self, f):
        @wraps(f)
        def unmarshal_decorator(*args, **kwargs):
            flux_logger.debug("")
            flux_logger.debug(f"--- New request ({request.path})")
            json_data = request.get_json(
                silent=True
            )  # silent=True lets get_json return None even if mime-type is not application/json
            if json_data is None:
                json_data = {}
            _data_str = str(json_data)
            if "password" in _data_str:
                flux_logger.debug(f"Decoding request with a password in it using schema {self.schema()}")
            else:
                flux_logger.debug(f"Decoding request: {repr(json_data)} using schema {self.schema()}")
            try:
                unmarshal_result = self.schema().load(json_data)
            except ValidationError as e:
                response_data = FluxFailResponse(
                    request, payload={"error": e.normalized_messages(), "csrf_token": session.get_csrf_token()}
                )
                logger.warning(f"Error unmarshalling request using {self.schema}: {e.normalized_messages()}")
                if "password" in _data_str:
                    logger.debug(f"Failing request has a password in it, not logging JSON data")
                else:
                    logger.debug(f"Failing request JSON data:\n{json.dumps(json_data, indent=4, sort_keys=True)}")
                return jsonify(response_data.to_dict())
            if "password" in unmarshal_result:
                # A simple safeguard for if debug logging is ever activated in production
                _without_pw = dict(unmarshal_result)
                _without_pw["password"] = "REDACTED"
                flux_logger.debug(f"Decoded request: {_without_pw}")
            else:
                flux_logger.debug(f"Decoded request: {unmarshal_result}")
            kwargs.update(unmarshal_result)
            return f(*args, **kwargs)

        return unmarshal_decorator
