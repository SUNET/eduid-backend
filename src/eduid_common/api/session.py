#
# Copyright (c) 2016 NORDUnet A/S
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
#     3. Neither the name of the NORDUnet nor the names of its
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

import collections
from time import time
import os
import binascii

from flask import request, current_app
from flask.sessions import SessionInterface

from eduid_common.session.session import SessionManager


class NoSessionDataFoundException(Exception):
    pass


def manage(action):
    """
    Decorator which causes the session to be marked as modified, so that it
    will be saved at the end of the request.

    :param action: Whether the session data has been changed or just accessed.
                   When it has been changed, the call to session.commit()
                   implies setting the ttl on the backend, so there is no need
                   to set it explicitly.
    :type action: str ('accessed'|'changed')
    """
    def outer(wrapped):
        def accessed(session, *arg, **kw):
            renew_backend = action=='accessed'
            session.renew_ttl(renew_backend=renew_backend)
            return wrapped(session, *arg, **kw)
        accessed.__doc__ = wrapped.__doc__
        return accessed
    return outer


class Session(collections.MutableMapping):
    """
    Session implementing the flask.sessions.SessionMixin interface.
    It uses the Session defined in eduid_common.session.session
    to store the session data in redis.
    """

    def __init__(self, app, base_session, new=False):
        """
        :param app: the flask app
        :param base_session: The underlying session object
        :param new: whether the session is new or not.

        :type app: flask.Flask
        :type base_session: eduid_common.session.session.Session
        :type new: bool
        """
        self.app = app
        self._session = base_session
        self._created = time()
        self._new = new
        self._modified = False
        self._invalidated = False
        self._permanent = True

    @manage('accessed')
    def __getitem__(self, key, default=None):
        return self._session.__getitem__(key, default=None)

    @manage('changed')
    def __setitem__(self, key, value):
        self._session[key] = value
        self._session.commit()

    @manage('changed')
    def __delitem__(self, key):
        del self._session[key]
        self._session.commit()

    @manage('accessed')
    def __iter__(self):
        return self._session.__iter__()

    @manage('accessed')
    def __len__(self):
        return len(self._session)

    @manage('accessed')
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
    def permanent(self):
        """
        See flask.sessions.SessionMixin
        """
        return self._permanent

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

    @property
    def modified(self):
        """
        See flask.sessions.SessionMixin
        """
        return self._modified

    @modified.setter
    def modified(self, val):
        self._modified = val

    def persist(self):
        """
        Store the session data in the redis backend,
        and renew the ttl for it.
        """
        self._session.commit()

    def renew_ttl(self, renew_backend):
        """
        Reset the ttl for the session, both in the cookie and
        (if `renew_backend==True`) in the redis backend.

        :param renew_backend: whether to renew the ttl in the redis backend
        :type renew_backend: bool
        """
        if not self.modified:
            self.modified =True
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

    @manage('changed')
    def new_csrf_token(self):
        """
        Copied from pyramid_session.py
        """
        # only produce one csrf token by request
        token = getattr(request, '_csrft_', False)
        if not token:
            token = binascii.hexlify(os.urandom(20))
            request._csrft_ = token
        self['_csrft_'] = token
        self.persist()
        return token

    @manage('accessed')
    def get_csrf_token(self):
        """
        Copied from pyramid_session.py
        """
        token = self.get('_csrft_', None)
        if token is None:
            token = self.new_csrf_token()
        return token


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
            return None
        token = request.cookies.get(cookie_name, None)
        current_app.logger.debug('Session cookie {} == {}'.format(cookie_name, token))
        if token is None:
            # New session
            base_session = self.manager.get_session(data={})
            session = Session(app, base_session, new=True)
            current_app.logger.debug('Created new session {}'.format(session))
        else:
            # Existing session
            try:
                base_session = self.manager.get_session(token=token)
                session = Session(app, base_session, new=False)
                current_app.logger.debug('Loaded existing session {}'.format(session))
            except KeyError:
                # I (@john) approve of commit 974836137eb83fd163abe4d83b12a9c6033c127e
                # made to master by @ft
                base_session = self.manager.get_session(data = {})
                session = Session(app, base_session, new = True)
                current_app.logger.warning('Re-created missing session {}'.format(session))
                #raise NoSessionDataFoundException('No session data found')

        return session

    def save_session(self, app, session, response):
        """
        See flask.session.SessionInterface
        """
        session.persist()
        session.set_cookie(response)
