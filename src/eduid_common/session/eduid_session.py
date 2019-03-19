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

from collections.abc import MutableMapping
from collections import defaultdict
from time import time
from flask import current_app, Flask
from flask import request as flask_request
from flask.sessions import SessionInterface, SessionMixin


from eduid_common.api.exceptions import BadConfiguration
from eduid_common.session.redis_session import SessionManager, RedisEncryptedSession


class EduidSession(SessionMixin, MutableMapping):
    """
    Session implementing the flask.sessions.SessionMixin interface.
    It uses the Session defined in eduid_common.session.session
    to store the session data in redis.
    """

    def __init__(self, app: Flask, base_session: RedisEncryptedSession, new: bool = False):
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
        if self.app.debug:
            self._history: SessionHistory = SessionHistory(self)

        # From SessionMixin
        self.permanent = True
        self.modified = False

    def __getitem__(self, key, default=None):
        return self._session.__getitem__(key, default=None)

    def __setitem__(self, key, value):
        if key not in self._session or self._session[key] != value:
            if self.app.debug:
                self._history[key] = value
            self._session[key] = value
            self.modified = True

    def __delitem__(self, key):
        if key in self._session:
            if self.app.debug:
                del self._history[key]
            del self._session[key]
            self.modified = True

    def __iter__(self):
        return self._session.__iter__()

    def __len__(self):
        return len(self._session)

    def __contains__(self, key):
        return self._session.__contains__(key)

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
        max_age = int(self.app.config.get('PERMANENT_SESSION_LIFETIME'))
        response.set_cookie(cookie_name,
                            value=self.token,
                            domain=cookie_domain,
                            path=cookie_path,
                            secure=cookie_secure,
                            httponly=cookie_httponly,
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

    def persist(self):
        """
        Store the session data in the redis backend,
        and renew the ttl for it.

        Check that session_id exists - when e.g. the account is being terminated,
        the session has already been invalidated at this point.
        """
        if self.new or self.modified:
            if self._session.session_id is not None:
                if self.app.debug:
                    self.app.logger.debug('Saving session')
                    self.app.logger.debug(self._history)
                self._session.commit()


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

    def open_session(self, app, request):
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
            except (KeyError, ValueError):
                current_app.logger.warning('Failed to load session from token {}'.format(token))

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


class SessionHistory(MutableMapping):

    def __init__(self, sess):
        self._session = sess
        self._history: dict = defaultdict(list)

    def __getitem__(self, key):
        return self._history.__getitem__(key)

    def __setitem__(self, key, value):
        if key in self._session and self._session[key] != value:
            self._history[key].append(self._session[key])
        self._history[key].append(value)

    def __delitem__(self, key):
        if key in self._session:
            self._history[key].append('Deleted')

    def __iter__(self):
        return self._history.__iter__()

    def __len__(self):
        return len(self._history)

    def __contains__(self, key):
        return self._history.__contains__(key)

    def __str__(self):
        out = ['Session content history']
        for key in self._history.keys():
            out.append(f'session[{key}] = {self._session[key]}')
            out.append(f'\t Previous values: {[value for value in self._history[key] if value != self._session[key]]}')
        return '\n'.join(out)
