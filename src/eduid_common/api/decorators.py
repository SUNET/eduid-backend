# -*- coding: utf-8 -*-

from __future__ import absolute_import

from functools import wraps
from flask import session, abort, current_app
from eduid_userdb.exceptions import UserDoesNotExist, MultipleUsersReturned
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


def require_user(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        eppn = session.get('user_eppn', None)
        if not eppn:
            raise ApiException('Not authorized', status_code=401)
        # Get user from central database
        try:
            user = current_app.central_userdb.get_user_by_eppn(eppn, raise_on_missing=True)
            kwargs['user'] = user
            return f(*args, **kwargs)
        except UserDoesNotExist as e:
            current_app.logger.error('Could not find user central database.')
            current_app.logger.error(e)
            raise ApiException('Not authorized', status_code=401)
        except MultipleUsersReturned as e:
            current_app.logger.error('Found multiple users in central database.')
            current_app.logger.error(e)
            raise ApiException('Not authorized', status_code=401)
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
