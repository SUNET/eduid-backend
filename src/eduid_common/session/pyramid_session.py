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

import os, binascii
import collections
from time import time
from eduid_common.session.session import SessionManager

import logging
logger = logging.getLogger(__name__)


def manage(action):
    '''
    Decorator which causes a cookie to be set when a session method
    is called.

    :param action: Whether the session data has been changed or just accessed.
                   When it has been changed, the call to session.commit()
                   implies setting the ttl on the backend, so there is no need
                   to set it explicitly.
    :type action: str ('accessed'|'changed')
    '''
    def outer(wrapped):
        def accessed(session, *arg, **kw):
            renew_backend = action == 'accessed'
            session.renew_ttl(renew_backend=renew_backend)
            return wrapped(session, *arg, **kw)
        accessed.__doc__ = wrapped.__doc__
        return accessed
    return outer


class SessionFactory(object):
    '''
    Session factory implementing the pyramid.interfaces.ISessionFactory
    interface.
    It uses the SessionManager defined in eduid_common.session.session
    to create sessions backed by redis.
    '''

    def __init__(self, settings):
        '''
        SessionFactory constructor.

        :param settings: the pyramid settings
        :type settings: dict
        '''
        cookie_max_age = int(settings.get('session.cookie_max_age'))
        # make sure that the data in redis outlives the session cookie
        session_ttl = 2 * cookie_max_age
        secret = settings.get('session.secret')
        self.manager = SessionManager(settings, ttl=session_ttl, secret=secret)

    def __call__(self, request):
        '''
        Create a session object for the given request.

        :param request: the request
        :type request: pyramid.request.Request

        :return: the session
        :rtype: Session
        '''
        raise NotImplementedError()


class Session(collections.MutableMapping):
    '''
    Session implementing the pyramid.interfaces.ISession interface.
    It uses the Session defined in eduid_common.session.session
    to store the session data in redis.
    '''

    def __init__(self, request, base_session, new=False):
        '''
        :param request: the request
        :type request: pyramid.request.Request
        :param base_session: The underlying session object
        :type base_session: eduid_common.session.session.RedisEncryptedSession
        :param new: whether the session is new or not.
        :type new: bool
        '''
        self.request = request
        self._session = base_session
        self._created = time()
        self._new = new
        self._ttl_reset = False

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
    def created(self):
        '''
        See pyramid.interfaces.ISession
        '''
        return self._created

    @property
    def new(self):
        '''
        See pyramid.interfaces.ISession
        '''
        return self._new

    def invalidate(self):
        '''
        See pyramid.interfaces.ISession
        '''
        self._session.clear()
        name = self.request.registry.settings.get('session.key')
        domain = self.request.registry.settings.get('session.cookie_domain')
        path = self.request.registry.settings.get('session.cookie_path')

        def rm_cookie_callback(request, response):
            response.set_cookie(
                    name=name,
                    value=None,
                    domain=domain,
                    path=path,
                    max_age=0
                    )
            return True

        self.request.add_response_callback(rm_cookie_callback)

    def changed(self):
        '''
        See pyramid.interfaces.ISession
        '''
        self._session.commit()

    @manage('changed')
    def flash(self, msg, queue='', allow_duplicate=True):
        '''
        See pyramid.interfaces.ISession
        '''
        if not queue:
            queue = 'default'
        if 'flash_messages' not in self._session:
            self._session['flash_messages'] = {'default': []}
        if queue not in self._session['flash_messages']:
            self._session['flash_messages'][queue] = []
        if not allow_duplicate:
            if msg in self._session['flash_messages'][queue]:
                return
        self._session['flash_messages'][queue].append(msg)
        self._session.commit()

    @manage('changed')
    def pop_flash(self, queue=''):
        '''
        See pyramid.interfaces.ISession
        '''
        if not queue:
            queue = 'default'
        if 'flash_messages' not in self._session:
            self._session['flash_messages'] = {'default': []}
        if queue in self._session['flash_messages']:
            msgs = self._session['flash_messages'].pop(queue)
            self._session.commit()
            return msgs
        return []

    @manage('accessed')
    def peek_flash(self, queue=''):
        '''
        See pyramid.interfaces.ISession
        '''
        if not queue:
            queue = 'default'
        if 'flash_messages' not in self._session:
            self._session['flash_messages'] = {'default': []}
        return self._session['flash_messages'].get(queue, [])

    @manage('changed')
    def new_csrf_token(self):
        '''
        See pyramid.interfaces.ISession
        '''
        token = binascii.hexlify(os.urandom(20))
        self['_csrft_'] = token
        self._session.commit()
        return token

    @manage('accessed')
    def get_csrf_token(self):
        '''
        See pyramid.interfaces.ISession
        '''
        token = self.get('_csrft_', None)
        if token is None:
            token = self.new_csrf_token()
        return token

    def persist(self):
        '''
        Store the session data in the redis backend,
        and renew the ttl for it.
        '''
        self._session.commit()

    def renew_ttl(self, renew_backend):
        '''
        Reset the ttl for the session, both in the cookie and
        (if `renew_backend==True`) in the redis backend.

        :param renew_backend: whether to renew the ttl in the redis backend
        :type renew_backend: bool
        '''
        if not self._ttl_reset:
            self.set_cookie()
            if renew_backend:
                self._session.renew_ttl()
            self._ttl_reset = True

    def set_cookie(self):
        '''
        Set the session cookie with the token
        '''
        token = self._session.token
        settings = self.request.registry.settings
        session_name = settings.get('session.key')
        domain = settings.get('session.cookie_domain')
        path = settings.get('session.cookie_path')
        secure = settings.get('session.cookie_secure')
        httponly = settings.get('session.cookie_httponly')
        max_age = settings.get('session.cookie_max_age')

        def set_cookie_callback(request, response):
            response.set_cookie(
                    name=session_name,
                    value=token,
                    domain=domain,
                    path=path,
                    secure=secure,
                    httponly=httponly,
                    max_age=max_age
                    )
            return True

        self.request.add_response_callback(set_cookie_callback)

    def delete(self):
        '''
        alias for invalidate
        '''
        self.invalidate()
