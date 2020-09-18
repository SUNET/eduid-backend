#
# Copyright (c) 2016 NORDUnet A/S
# Copyright (c) 2018, 2020 SUNET
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
"""
Applications that need to store state in a distributed fashion can
use this module.

Basic usage:

    manager = SessionManager(redis_config, secret=app_secret)
    session = manager.get_session()
    session['foo'] = 'bar'
    session.commit()
    set_cookie(session.token.cookie_val)

Sessions are stored in a Redis backend (the currently deployed one
in eduID has three servers, one master and two slaves, and uses
Redis sentinel for high availability).

Since Redis does not do authorization, and to prevent data leakage
if the Redis server would get compromised, all data stored in Redis
is signed and encrypted. The current implementation uses the NaCl
crypto library to conveniently handle this.

To be able to load a session from Redis, one needs the application
specific key which is expected to be shared by all instances of an
application that needs to share session state, and the cookie from
the user since it contains a per-session secret key (derived from the
session_id).

When the session id is shared with the user it is in the form of a
token. The token is the session id plus an HMAC signature of the
session id. The HMAC key is also derived from the application key
and the session id, but it is not the same as the session encryption
key.

The token has to be a valid XML NCName since pysaml2 will use it
in such a way. That means it has to start with a letter and can't
contain certain characters. For this reason, the format used for
tokens is

  'a' + base32(session_id + hmac + padding)

the padding made up so that base32 does not need to pad itself by
appending equal-signs ('=') at the end, since that is not allowed
in an NCName.
"""
from __future__ import annotations

import collections.abc
import json
import logging
from typing import Any, Dict, List, Mapping, Optional

import nacl.encoding
import nacl.secret
import nacl.utils
import redis
import redis.sentinel
from saml2.saml import NameID

from eduid_common.session.session_cookie import SessionCookie, derive_key

logger = logging.getLogger(__name__)


class SessionManager(object):
    """
    Factory objects that hold some configuration data and provide
    session objects.
    """

    def __init__(
        self,
        cfg: Mapping[str, Any],
        app_secret: str,
        ttl: int = 600,
        whitelist: Optional[List[str]] = None,
        raise_on_unknown: bool = False,
    ):
        """
        Constructor for SessionManager

        :param cfg: Redis connection settings dict
        :param app_secret: Shared secret for all instances of a particular application
        :param ttl: The time to live for the sessions
        :param whitelist: list of allowed keys for the sessions
        :param raise_on_unknown: Whether to raise an exception on an attempt
                                 to set a session session_id not in whitelist

        :type cfg: dict
        :type ttl: int
        :type app_secret: str
        :type whitelist: list
        :type raise_on_unknown: bool
        """
        self.pool = get_redis_pool(cfg)
        self.ttl = ttl
        self.secret = app_secret
        # TODO: whitelist and raise_on_unknown is unused functionality. Remove?
        self.whitelist = whitelist
        self.raise_on_unknown = raise_on_unknown

    def _get_connection(self) -> redis.StrictRedis:
        """
        Get a Redis connection.

        Done in a separate function so that this class can be subclassed in test cases.
        """
        return redis.StrictRedis(connection_pool=self.pool)

    def get_session(self, cookie_val: Optional[str] = None) -> RedisEncryptedSession:
        """
        Create or fetch a session for the given token or data.

        :param cookie_val: the value of the session cookie, if any

        :return: the session
        """
        conn = self._get_connection()

        res = RedisEncryptedSession(
            conn,
            cookie_val=cookie_val,
            app_secret=self.secret,
            ttl=self.ttl,
            whitelist=self.whitelist,
            raise_on_unknown=self.raise_on_unknown,
        )

        if cookie_val:
            if not res.load_session():
                logger.warning(f'Session cache miss for cookie {cookie_val}')
                raise KeyError(f'Session not found using provided cookie')
        else:
            logger.debug(f'Created new session {res.token}')

        return res


def get_redis_pool(cfg):
    port = cfg['redis_port']
    if cfg.get('redis_sentinel_hosts') and cfg.get('redis_sentinel_service_name'):
        _hosts = cfg['redis_sentinel_hosts']
        _name = cfg['redis_sentinel_service_name']
        host_port = [(x, port) for x in _hosts]
        manager = redis.sentinel.Sentinel(host_port, socket_timeout=0.1)
        pool = redis.sentinel.SentinelConnectionPool(_name, manager)
    else:
        db = cfg['redis_db']
        host = cfg['redis_host']
        pool = redis.ConnectionPool(host=host, port=port, db=db)
    return pool


class NameIDEncoder(json.JSONEncoder):
    # TODO: This enables us to serialise NameIDs into the stored sessions,
    #       but we don't seem to de-serialise them on load
    def default(self, obj):
        if isinstance(obj, NameID):
            return str(obj)
        return json.JSONEncoder.default(self, obj)


class NoSessionDataFoundException(Exception):
    # TODO: This is never raised, which might be a bug since we have code to explicitly catch it
    pass


class RedisEncryptedSession(collections.abc.MutableMapping):
    """
    Session objects that keep their data in a redis db.
    """

    def __init__(
        self,
        conn: redis.StrictRedis,
        app_secret: str,
        ttl: int,
        cookie_val: Optional[str] = None,
        whitelist: Optional[List[str]] = None,
        raise_on_unknown: bool = False,
    ):
        """
        Create an empty session object.

        If a user provided cookie is available, a subsequent call to `load_session` can be
        used to retrieve the session data.

        If whitelist is provided, no keys will be set unless they are
        explicitly listed in it; and if raise_on_unknown is True,
        a ValueError will be raised on every attempt to set a
        non-whitelisted key.

        :param conn: Redis connection instance
        :param app_secret: Application secret key used to sign the session_id associated
                       with the session
        :param ttl: The time to live for the session
        :param cookie_val: the token containing the session_id for the session
        :param whitelist: list of allowed keys for the sessions
        :param raise_on_unknown: Whether to raise an exception on an attempt
                                 to set a session key not in whitelist
        """
        self.conn = conn
        self.ttl = ttl
        self.whitelist = whitelist
        self.raise_on_unknown = raise_on_unknown
        self.app_secret = app_secret

        if cookie_val:
            self.token = SessionCookie.from_cookie(cookie_val, app_secret=self.app_secret)
        else:
            self.token = SessionCookie.new(app_secret=self.app_secret)

        _nacl_key = derive_key(self.app_secret, self.token.session_id, 'nacl', nacl.secret.SecretBox.KEY_SIZE)
        self.secret_box = nacl.secret.SecretBox(_nacl_key)

        self._data: dict = {}

    def load_session(self) -> bool:
        logger.debug(f'Looking for session {self.token}')

        # Fetch session from session store (Redis)
        _encrypted_data = self.conn.get(self.token.session_id)
        if not _encrypted_data:
            return False

        self._data = self.decrypt_data(_encrypted_data)

        return True

    def __getitem__(self, key, default=None):
        if key in self._data:
            return self._data[key]
        elif default is not None:
            return default
        raise KeyError(f'Key {repr(key)} not present in session')

    def __setitem__(self, key, value):
        if self.whitelist and key not in self.whitelist:
            if self.raise_on_unknown:
                raise ValueError(f'Key {repr(key)} not allowed in session')
            return
        self._data[key] = value

    def __delitem__(self, key):
        del self._data[key]

    def __iter__(self):
        return self._data.__iter__()

    def __len__(self):
        return len(self._data)

    def __contains__(self, key):
        return self._data.__contains__(key)

    def commit(self):
        """
        Persist the currently held data into the redis db.
        """
        data = self.encrypt_data(self._data)
        logger.debug(f'Committing session {self.token} to the cache with ttl {self.ttl} ({len(data)} bytes)')
        self.conn.setex(self.token.session_id, self.ttl, data)

    def encrypt_data(self, data_dict: Mapping[str, Any]) -> str:
        """
        Sign and encrypt data before storing it in Redis.

        :param data_dict: Data to be stored
        :return: serialized data
        """
        logger.debug(f'Storing data in cache[{self.token}]:\n{repr(data_dict)}')
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        # Version data to make it easier to know how to decode it on reading
        data_json = json.dumps(data_dict, cls=NameIDEncoder)
        versioned = {
            'v2': bytes(
                self.secret_box.encrypt(data_json.encode('ascii'), nonce, encoder=nacl.encoding.Base64Encoder)
            ).decode('ascii')
        }
        return json.dumps(versioned)

    def decrypt_data(self, data_str: str) -> Dict[str, Any]:
        """
        Decrypt and verify session data read from Redis.

        :param data_str: Data read from Redis
        :return: Parsed data as dict
        """
        versioned = json.loads(data_str)
        if 'v2' in versioned:
            _data = self.secret_box.decrypt(versioned['v2'], encoder=nacl.encoding.Base64Encoder)
            decrypted = json.loads(_data)
            logger.debug(f'Loaded data from cache[{self.token}]:\n{repr(decrypted)}')
            return decrypted

        logger.error(f'Unknown data retrieved from cache[{self.token}]: {repr(data_str)}')
        raise ValueError('Unknown data retrieved from cache')

    def clear(self):
        """
        Discard all data contained in the session.
        """
        self._data = {}
        self.conn.delete(self.token.session_id)
        self.token = None

    def renew_ttl(self):
        """
        Restart the ttl countdown
        """
        self.conn.expire(self.token.session_id, self.ttl)

    def to_dict(self) -> dict:
        return dict(self._data)
