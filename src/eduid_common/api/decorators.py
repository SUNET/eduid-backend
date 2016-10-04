# -*- coding: utf-8 -*-

from __future__ import absolute_import

from functools import wraps
from flask import session, abort, current_app, request, jsonify
from marshmallow.exceptions import ValidationError
from eduid_userdb.exceptions import UserDoesNotExist, MultipleUsersReturned
from eduid_common.api.utils import retrieve_modified_ts
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_common.api.schemas.models import FluxSuccessResponse, FluxFailResponse
from eduid_common.api.exceptions import ApiException

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
        raise ApiException('Not authorized', status_code=401)
    return decorated_function


def _get_user():
    eppn = session.get('user_eppn', None)
    if not eppn:
        raise ApiException('Not authorized', status_code=401)
    # Get user from central database
    try:
        return current_app.central_userdb.get_user_by_eppn(eppn, raise_on_missing=True)
    except UserDoesNotExist as e:
        current_app.logger.error('Could not find user central database.')
        current_app.logger.error(e)
        raise ApiException('Not authorized', status_code=401)
    except MultipleUsersReturned as e:
        current_app.logger.error('Found multiple users in central database.')
        current_app.logger.error(e)
        raise ApiException('Not authorized', status_code=401)


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
        user = _get_user()
        retrieve_modified_ts(user, current_app.dashboard_userdb)
        kwargs['user'] = user
        return f(*args, **kwargs)
    return decorated_function


def require_support_personnel(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        eppn = session.get('user_eppn', None)

        # If the logged in user is whitelisted then we
        # pass on the request to the decorated view
        # together with the eppn of the logged in user.
        if eppn in current_app.config['SUPPORT_PERSONNEL']:
            kwargs['logged_in_user'] = eppn
            return f(*args, **kwargs)
        current_app.logger.warning('{!s} not in support personnel whitelist: {!s}'.format(
            eppn, current_app.config['SUPPORT_PERSONNEL']))
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

            # Handle fail responses
            if ret.pop('fail', False):
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
            except ValidationError as e:
                response_data = FluxFailResponse(request, payload={'error': e.normalized_messages()})
                return jsonify(response_data.to_dict())
            return f(*args, **kwargs)
        return decorated_function

