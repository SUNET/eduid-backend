# -*- coding: utf-8 -*-

from __future__ import absolute_import

import warnings
from werkzeug.wrappers import Response as WerkzeugResponse
from functools import wraps
from flask import session, abort, current_app, request, jsonify
from marshmallow.exceptions import ValidationError
from eduid_userdb.exceptions import UserDoesNotExist, MultipleUsersReturned
from eduid_common.api.utils import get_user
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_common.api.schemas.models import FluxResponseStatus, FluxSuccessResponse, FluxFailResponse

__author__ = 'lundberg'


def require_eppn(f):
    @wraps(f)
    def require_eppn_decorator(*args, **kwargs):
        eppn = session.get('user_eppn', None)
        # If the user is logged in and has a session
        # pass on the request to the decorated view
        # together with the eppn of the logged in user.
        if eppn:
            kwargs['eppn'] = eppn
            return f(*args, **kwargs)
        abort(401)
    return require_eppn_decorator


def require_user(f):
    @wraps(f)
    def require_user_decorator(*args, **kwargs):
        user = get_user()
        kwargs['user'] = user
        return f(*args, **kwargs)
    return require_user_decorator


def require_support_personnel(f):
    @wraps(f)
    def require_support_decorator(*args, **kwargs):
        user = get_user(private_userdb=False)
        # If the logged in user is whitelisted then we
        # pass on the request to the decorated view
        # together with the eppn of the logged in user.
        if user.eppn in current_app.config['SUPPORT_PERSONNEL']:
            kwargs['support_user'] = user
            return f(*args, **kwargs)
        current_app.logger.warning('{!s} not in support personnel whitelist: {!s}'.format(
            user, current_app.config['SUPPORT_PERSONNEL']))
        # Anything else is considered as an unauthorized request
        abort(403)
    return require_support_decorator


def can_verify_identity(f):
    @wraps(f)
    def verify_identity_decorator(*args, **kwargs):
        user = get_user()
        # For now a user can just have one verified NIN
        if user.nins.primary is not None:
            ret = {'error': 'User is already verified'}
            response_data = FluxFailResponse(request, payload=ret)
            return jsonify(FluxStandardAction().dump(response_data.to_dict()).data)
        # A user can not verify a nin if another previously was verified
        locked_nin = user.locked_identity.find('nin')
        if locked_nin and locked_nin.number != kwargs['nin']:
            ret = {'error': 'Another nin is already registered for this user'}
            response_data = FluxFailResponse(request, payload=ret)
            return jsonify(FluxStandardAction().dump(response_data.to_dict()).data)

        return f(*args, **kwargs)

    return verify_identity_decorator


class MarshalWith(object):

    def __init__(self, schema):
        self.schema = schema

    def __call__(self, f):
        @wraps(f)
        def marshal_decorator(*args, **kwargs):
            ret = f(*args, **kwargs)

            if isinstance(ret, WerkzeugResponse):  # No need to Marshal again, someone else already did that
                return ret

            try:
                response_status = ret.pop('_status', FluxResponseStatus.ok)
            # ret may be a list:
            except TypeError:
                for item in ret:
                    response_status = item.pop('_status', FluxResponseStatus.ok)
                    if response_status != FluxResponseStatus.ok:
                        break

            # Handle fail responses
            if response_status != FluxResponseStatus.ok:
                response_data = FluxFailResponse(request, payload=ret)
                return jsonify(FluxStandardAction().dump(response_data.to_dict()).data)

            # Handle success responses
            response_data = FluxSuccessResponse(request, payload=ret)
            return jsonify(self.schema().dump(response_data.to_dict()).data)
        return marshal_decorator


class UnmarshalWith(object):

    def __init__(self, schema):
        self.schema = schema

    def __call__(self, f):
        @wraps(f)
        def unmarshal_decorator(*args, **kwargs):
            try:
                json_data = request.get_json()
                if json_data is None:
                    json_data = {}
                unmarshal_result = self.schema().load(json_data)
                kwargs.update(unmarshal_result.data)
                return f(*args, **kwargs)
            except ValidationError as e:
                response_data = FluxFailResponse(request, payload={'error': e.normalized_messages()})
                return jsonify(response_data.to_dict())
        return unmarshal_decorator


class Deprecated(object):
    """
    Mark deprecated functions with this decorator.
    
    Attention! Use it as the closest one to the function you decorate.

    :param message: The deprecation message
    :type message: str | unicode
    """

    def __init__(self, message=None):
        self.message = message

    def __call__(self, func):
        if self.message is None:
            self.message = 'Deprecated function {!r} called'.format(func.__name__)

        @wraps(func)
        def new_func(*args, **kwargs):
            warnings.warn(self.message, category=DeprecationWarning, stacklevel=2)
            return func(*args, **kwargs)

        # work around a bug in functools.wraps thats fixed in python 3.2
        if getattr(new_func, '__wrapped__', None) is None:
            new_func.__wrapped__ = func
        return new_func
