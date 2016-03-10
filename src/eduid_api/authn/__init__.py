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

from flask import Flask
from flask.sessions import SessionInterface

from eduid_api.authn.config import AuthnConfigParser
from eduid_common.session.session import SessionManager


app = Flask('eduID authn')
config_parser = AuthnConfigParser('eduid-authn.ini',
                                  config_environment_variable='EDUID_CONFIG')
config = config_parser.read_configuration()
app.config.update(config)



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

    def __init__(self, app, request, base_session, new=False):
        """
        :param app: the flask app
        :param request: the request
        :param base_session: The underlying session object
        :param new: whether the session is new or not.

        :type app: flask.Flask
        :type request: flask.Request
        :type base_session: eduid_common.session.session.Session
        :type new: bool
        """
        self.app = app
        self.request = request
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
        self.modified =True
        self._invalidated = True
        self._session.clear()


class SessionFactory(SessionInterface):
    """
    """
    def __init__(self, config):

        self.config = config
        secret = config['SECRET_KEY']
        ttl_sec = 2 * int(config['PERMANENT_SESSION_LIFETIME'])
        ttl_min = int(ttl_sec / 60)
        self.manager = SessionManager(config, ttl=ttl_min, secret=secret)

    def open_session(self, app, request):
        try:
            cookie_name = app.config['SESSION_COOKIE_NAME']
        except KeyError:
            return None
        token = request.cookies.get(cookie_name, None)
        if token is None:
            base_session = self.manager.get_session(data={})
        else:
            base_session = self.manager.get_session(token=token)

    def save_session(self, app, session, response):
        session.persist()

        cookie_name = self.config.get('SESSION_COOKIE_NAME')
        cookie_domain = self.config.get('SESSION_COOKIE_DOMAIN')
        cookie_path = self.config.get('SESSION_COOKIE_PATH')
        cookie_secure = self.config.get('SESSION_COOKIE_SECURE')
        cookie_httponly = self.config.get('SESSION_COOKIE_HTTPONLY')
        max_age = self.config.get('PERMANENT_SESSION_LIFETIME')
        response.set_cookie(cookie_name,
                            value = session.token,
                            domain = cookie_domain,
                            path = cookie_path,
                            secure = cookie_secure,
                            httponly = cookie_httponly,
                            max_age = max_age
                            )


app.session_interface = SessionFactory(config)


@app.route('/')
def index():
    return 'ho ho ho'


if __name__ ==  '__main__':
    app.run()
