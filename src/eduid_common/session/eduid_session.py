#
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#
#

import os
import binascii
import json

from collections.abc import MutableMapping
from time import time
from typing import Optional
from flask import current_app
from flask import request as flask_request
from flask.sessions import SessionInterface, SessionMixin

from eduid_common.config.exceptions import BadConfiguration
from eduid_common.config.app import EduIDApp
from eduid_common.session.redis_session import SessionManager, RedisEncryptedSession
from eduid_common.session.namespaces import SessionNSBase, Common, MfaAction
from eduid_common.session.namespaces import Signup, Actions
from eduid_common.session.logindata import SSOLoginData


class EduidSession(SessionMixin, MutableMapping):
    """
    Session implementing the flask.sessions.SessionMixin interface.
    It uses the Session defined in eduid_common.session.session
    to store the session data in redis.
    """

    def __init__(self, app: EduIDApp, base_session: RedisEncryptedSession, new: bool = False):
        """
        :param app: the flask app
        :param base_session: The underlying session object
        :param new: whether the session is new or not.
        """
        super().__init__()
        self.app = app
        self._session = base_session
        self._created = time()
        self._new = new
        self._invalidated = False

        # From SessionMixin
        self.permanent = True
        self.modified = False

        # Namespaces
        self._common: Optional[Common] = None
        self._mfa_action: Optional[MfaAction] = None
        self._signup: Optional[Signup] = None
        self._actions: Optional[Actions] = None
        self._sso_ticket: Optional[SSOLoginData] = None

    def __getitem__(self, key, default=None):
        return self._session.__getitem__(key, default=None)

    def __setitem__(self, key, value):
        if key not in self._session or self._session[key] != value:
            self._session[key] = value
            self.modified = True
            if self.app.debug:
                self.app.logger.debug(f'SET session[{key}] = {value}')

    def __delitem__(self, key):
        if key in self._session:
            del self._session[key]
            self.modified = True
            if self.app.debug:
                self.app.logger.debug(f'DEL session[{key}]')

    def __iter__(self):
        return self._session.__iter__()

    def __len__(self):
        return len(self._session)

    def __contains__(self, key):
        return self._session.__contains__(key)

    @property
    def common(self) -> Optional[Common]:
        if not self._common:
            self._common = Common.from_dict(self._session.get('_common', {}))
        return self._common

    @common.setter
    def common(self, value: Optional[Common]):
        if not self._common:
            self._common = value

    @property
    def mfa_action(self) -> Optional[MfaAction]:
        if not self._mfa_action:
            self._mfa_action = MfaAction.from_dict(self._session.get('_mfa_action', {}))
        return self._mfa_action

    @mfa_action.setter
    def mfa_action(self, value: Optional[MfaAction]):
        if not self._mfa_action:
            self._mfa_action = value

    @mfa_action.deleter
    def mfa_action(self):
        self._mfa_action = None
        self._session.pop('_mfa_action', None)
        self.modified = True

    @property
    def signup(self) -> Optional[Signup]:
        if not self._signup:
            self._signup = Signup.from_dict(self._session.get('_signup', {}))
        return self._signup

    @signup.setter
    def signup(self, value: Optional[Signup]):
        if not self._signup:
            self._signup = value

    @property
    def actions(self) -> Optional[Actions]:
        if not self._actions:
            self._actions = Actions.from_dict(self._session.get('_actions', {}))
        return self._actions

    @actions.setter
    def actions(self, value: Optional[Actions]):
        if not self._actions:
            self._actions = value

    @property
    def sso_ticket(self) -> Optional[SSOLoginData]:
        if not self._sso_ticket:
            self._sso_ticket = SSOLoginData.from_dict(self._session.get('_sso_ticket', {}))
        return self._sso_ticket

    @sso_ticket.setter
    def sso_ticket(self, value: Optional[SSOLoginData]):
        if not self._sso_ticket:
            self._sso_ticket = value

    @property
    def token(self):
        """
        Return the token in the session,
        or the empty string if the session has been invalidated.
        """
        if self._invalidated:
            return ''
        return self._session.token

    @property
    def new(self):
        """
        See flask.sessions.SessionMixin
        """
        return self._new

    @property
    def created(self):
        """
        Created timestamp
        """
        return self._created

    def renew_ttl(self, renew_backend):
        """
        Reset the ttl for the session, both in the cookie and
        (if `renew_backend==True`) in the redis backend.

        :param renew_backend: whether to renew the ttl in the redis backend
        :type renew_backend: bool
        """
        if not self.modified:
            self.modified = True
            if renew_backend:
                self._session.renew_ttl()

    def invalidate(self):
        """
        Invalidate the session. Clear the data from redis,
        and set an empty session cookie.
        """
        self.modified = True
        self._invalidated = True
        self._session.clear()

    def set_cookie(self, response):
        """
        Set the session cookie.

        :param response: the response  object to carry the cookie
        :type response: flask.Response
        """
        cookie_name = self.app.config.get('SESSION_COOKIE_NAME')
        cookie_domain = self.app.config.get('SESSION_COOKIE_DOMAIN')
        cookie_path = self.app.config.get('SESSION_COOKIE_PATH')
        cookie_secure = self.app.config.get('SESSION_COOKIE_SECURE')
        cookie_httponly = self.app.config.get('SESSION_COOKIE_HTTPONLY')
        cookie_samesite = self.app.config.get('SESSION_COOKIE_SAMESITE')
        max_age = int(self.app.config.get('PERMANENT_SESSION_LIFETIME'))
        response.set_cookie(cookie_name,
                            value=self.token,
                            domain=cookie_domain,
                            path=cookie_path,
                            secure=cookie_secure,
                            httponly=cookie_httponly,
                            samesite=cookie_samesite,
                            max_age=max_age
                            )

    def new_csrf_token(self):
        """
        Copied from pyramid_session.py
        """
        # only produce one csrf token by request
        token = getattr(flask_request, '_csrft_', False)
        if not token:
            token = binascii.hexlify(os.urandom(20)).decode('ascii')
            flask_request._csrft_ = token
        self['_csrft_'] = token
        self.persist()
        return token

    def get_csrf_token(self):
        """
        Copied from pyramid_session.py
        """
        token = self.get('_csrft_', None)
        if token is None:
            token = self.new_csrf_token()
        return token

    def _serialize_namespaces(self):
        for key in self.__dict__.keys():
            if key.startswith('_'):  # Keep SessionNS in sunder attrs
                attr = getattr(self, key)
                if isinstance(attr, SessionNSBase):
                    self[key] = attr.to_dict()

    def persist(self):
        """
        Store the session data in the redis backend,
        and renew the ttl for it.

        Check that session_id exists - when e.g. the account is being terminated,
        the session has already been invalidated at this point.
        """
        # Serialize namespace dataclasses to see if their content changed
        self._serialize_namespaces()

        if self.new or self.modified:
            if self._session.session_id is not None:
                self._session.commit()
                if self.app.debug:
                    _saved_data = json.dumps(self._session.to_dict(), indent=4, sort_keys=True)
                    self.app.logger.debug(f'Saved session:\n{_saved_data}')
            else:
                self.app.logger.warning('Tried to persist a session with no session id')


class SessionFactory(SessionInterface):
    """
    Session factory, implementing flask.session.SessionInterface,
    to provide eduID redis-based sessions to the APIs.

    :param config: the configuration for the session
    :type config: dict
    """

    def __init__(self, config):

        self.config = config
        secret = config['SECRET_KEY']
        ttl = 2 * int(config['PERMANENT_SESSION_LIFETIME'])
        self.manager = SessionManager(config, ttl=ttl, secret=secret)

    #  Return type of "open_session" incompatible with supertype "SessionInterface"
    def open_session(self, app, request) -> EduidSession:  # type: ignore
        """
        See flask.session.SessionInterface
        """
        try:
            cookie_name = app.config['SESSION_COOKIE_NAME']
        except KeyError:
            app.logger.error('SESSION_COOKIE_NAME not set in config')
            raise BadConfiguration('SESSION_COOKIE_NAME not set in config')

        # Load token from cookie
        token = request.cookies.get(cookie_name, None)
        if app.debug:
            current_app.logger.debug('Session cookie {} == {}'.format(cookie_name, token))

        if token:
            # Existing session
            try:
                base_session = self.manager.get_session(token=token, debug=app.debug)
                sess = EduidSession(app, base_session, new=False)
                if app.debug:
                    current_app.logger.debug('Loaded existing session {}'.format(sess))
                return sess
            except (KeyError, ValueError) as exc:
                current_app.logger.warning(f'Failed to load session from token {token}: {exc}')

        # New session
        base_session = self.manager.get_session(data={}, debug=app.debug)
        sess = EduidSession(app, base_session, new=True)
        if app.debug:
            current_app.logger.debug('Created new session {}'.format(sess))
        return sess

    def save_session(self, app, sess, response):
        """
        See flask.session.SessionInterface
        """
        sess.persist()
        sess.set_cookie(response)
