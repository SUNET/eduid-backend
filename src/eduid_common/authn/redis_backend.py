#
# Copyright (c) 2015 NORDUnet A/S
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
from .abc import SessionBackend
from redis import WatchError


class RedisBackend(SessionBackend):
    '''
    Session and cache backend using redis.

    :param redis_conn: the redis client, possibly from a redis.ConnectionPool
    :type redis_conn: redis.Redis
    :param token: the token that identifies the session
    :type token: str
    '''

    def __init__(self, redis_conn, token):
        self.conn = redis_conn
        self.token = token
        self.session = self.conn.get(self.token)

    def __getitem__(self, key, default=None):
        return self.session.get(key, default)

    def __setitem__(self, key, value):
        # XXX
        # making this atomic is overkill, sessions are not shared if a same
        # user logs in from 2 devices, and the contents are immutable from the
        # point of view of the bussiness logic.
        with self.conn.pipeline() as pipe:
            while True:
                try:
                    pipe.watch(self.token)
                    session = pipe.get(self.token)
                    session[key] = value
                    pipe.multi()
                    pipe.set(self.token, session)
                    break
                except WatchError:
                    continue
        self.session = session

    def __delitem__(self, key):
        with self.conn.pipeline() as pipe:
            while True:
                try:
                    pipe.watch(self.token)
                    session = pipe.get(self.token)
                    del session[key]
                    pipe.multi()
                    pipe.set(self.token, session)
                    break
                except WatchError:
                    continue
        self.session = session

    def __iter__(self):
        return self.session.__iter__()

    def __len__(self):
        return self.session.__len__()
