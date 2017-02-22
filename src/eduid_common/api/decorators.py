# -*- coding: utf-8 -*-

from __future__ import absolute_import

import warnings
from functools import wraps
from flask import session, abort, current_app, request, jsonify
from marshmallow.exceptions import ValidationError
from eduid_userdb.exceptions import UserDoesNotExist, MultipleUsersReturned
from eduid_common.api.utils import retrieve_modified_ts, get_dashboard_user
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_common.api.schemas.models import FluxResponseStatus, FluxSuccessResponse, FluxFailResponse

__author__ = 'lundberg'


def require_eppn(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        eppn = session.get('user_eppn', None)
        # If the user is logged in and has a session
        # pass on the request to the decorated view
        # together with the eppn of the logged in user.
        if eppn:
            kwargs['eppn'] = eppn
            return f(*args, **kwargs)
        abort(401)
    return decorated_function


def _get_user():
    eppn = session.get('user_eppn', None)
    if not eppn:
        abort(401)
    # Get user from central database
    try:
        return current_app.central_userdb.get_user_by_eppn(eppn, raise_on_missing=True)
    except UserDoesNotExist as e:
        current_app.logger.error('Could not find user central database.')
        current_app.logger.error(e)
        abort(401)
    except MultipleUsersReturned as e:
        current_app.logger.error('Found multiple users in central database.')
        current_app.logger.error(e)
        abort(401)


def require_user(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = _get_user()
        kwargs['user'] = user
        return f(*args, **kwargs)
    return decorated_function


def require_dashboard_user(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_dashboard_user()
        kwargs['user'] = user
        return f(*args, **kwargs)
    return decorated_function


def require_support_personnel(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = _get_user()
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
    return decorated_function


class MarshalWith(object):

    def __init__(self, schema):
        self.schema = schema

    def __call__(self, f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ret = f(*args, **kwargs)
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
        return decorated_function


class UnmarshalWith(object):

    def __init__(self, schema):
        self.schema = schema

    def __call__(self, f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
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
        return decorated_function


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
