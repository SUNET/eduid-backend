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

To be able to decrypt a session from Redis, one needs the application
specific key which is expected to be shared by all instances of an
application that needs to share session state.

The sessions are encrypted with session encryption keys that are
derived from the session id (which is also the Redis key) plus the
application specific key.

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

import base64
import collections.abc
import hashlib
import hmac
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

import nacl.encoding
import nacl.secret
import nacl.utils
import redis
import redis.sentinel
from saml2.saml import NameID

logger = logging.getLogger(__name__)

# Prepend an 'a' so we always have a valid NCName,
# needed by pysaml2 for its session ids.
TOKEN_PREFIX = 'a'

HMAC_DIGEST_SIZE = 256 // 8
SESSION_KEY_BITS = 256


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
    def default(self, obj):
        if isinstance(obj, NameID):
            return str(obj)
        return json.JSONEncoder.default(self, obj)


class NoSessionDataFoundException(Exception):
    pass


@dataclass(frozen=True)
class SessionReference(object):
    cookie_val: str  # the value to store as a cookie in the user's browser (basically session_id + signature)
    session_id: str  # the lookup key used to locate the session in the session store
    signature: bytes = field(repr=False)  # cryptographic signature of session_id
    hmac_key: bytes = field(repr=False)  # key used to sign the session_id

    @classmethod
    def new(cls, app_secret: str):
        # Generate a random session_id
        _bin_session_id = nacl.utils.random(SESSION_KEY_BITS // 8)
        session_id = _bin_session_id.hex()
        _bin_hmac_key = derive_key(app_secret, session_id, 'hmac', HMAC_DIGEST_SIZE)
        _bin_signature = cls._sign_session_id(_bin_session_id, _bin_hmac_key)
        token = cls._encode_token(_bin_session_id, _bin_signature)
        return cls(token, session_id, _bin_signature, _bin_hmac_key)

    @classmethod
    def from_cookie(cls, cookie_val: str, app_secret: str):
        _bin_session_id, _bin_signature = cls._decode_cookie(cookie_val)
        session_id = _bin_session_id.hex()
        hmac_key = derive_key(app_secret, session_id, 'hmac', HMAC_DIGEST_SIZE)
        if not cls._verify_session_id(_bin_session_id, hmac_key, _bin_signature):
            raise ValueError('Token signature check failed')
        return cls(cookie_val, session_id, _bin_signature, hmac_key)

    @staticmethod
    def _encode_token(bin_session_id: bytes, signature: bytes) -> str:
        """
        Encode a session id and it's signature into a token that is stored
        in the users browser as a cookie.

        :return: a token with the signed session_id
        """
        # The last byte ('x') is padding to prevent b32encode from adding an = at the end
        combined = base64.b32encode(bin_session_id + signature + b'x')
        # Make sure token will be a valid NCName (pysaml2 requirement)
        while combined.endswith(b'='):
            combined = combined[:-1]
        return TOKEN_PREFIX + combined.decode('utf-8')

    @staticmethod
    def _decode_cookie(cookie_val: str) -> Tuple[bytes, bytes]:
        """
        Decode a token (token is what is stored in a cookie) into it's components.

        :param cookie_val: the token with the signed session_id

        :return: the session_id and signature
        """
        # the slicing is to remove a leading 'a' needed so we have a
        # valid NCName so pysaml2 doesn't complain when it uses the token as
        # session id.
        if not cookie_val.startswith(TOKEN_PREFIX):
            raise ValueError('Invalid token string {!r}'.format(cookie_val))
        val = cookie_val[len(TOKEN_PREFIX):]
        # Split the token into it's two parts - the session_id and the HMAC signature of it
        # (the last byte is ignored - it is padding to make b32encode not put an = at the end)
        _decoded = base64.b32decode(val)
        _bin_session_id, _bin_sig = _decoded[:HMAC_DIGEST_SIZE], _decoded[HMAC_DIGEST_SIZE:-1]
        return _bin_session_id, _bin_sig

    @staticmethod
    def _sign_session_id(session_id: bytes, signing_key: bytes) -> bytes:
        """
        Generate a HMAC signature of session_id using the session-unique signing key.

        :param session_id: Session id (Redis key)
        :param signing_key: Key for generating the signature

        :return: HMAC signature of session_id
        """
        return hmac.new(signing_key, session_id, digestmod=hashlib.sha256).digest()

    @classmethod
    def _verify_session_id(cls, session_id: bytes, signing_key: bytes, signature: bytes):
        """
        Verify the HMAC signature on a session_id using the session-unique signing key.

        :param session_id: Session id (Redis key)
        :param signing_key: Key for generating the signature
        :param signature: Signature of session_id

        :return: True if the signature matches, false otherwise
        :rtype: bool
        """
        calculated_sig = cls._sign_session_id(session_id, signing_key)

        # Avoid timing attacks, copied from Beaker https://beaker.readthedocs.org/
        invalid_bits = 0
        if len(calculated_sig) != len(signature):
            return None

        for a, b in zip(calculated_sig, signature):
            invalid_bits += a != b

        return bool(not invalid_bits)


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
        Retrieve or create a session for the given token or data.

        Preference order of parameter present:

            data:       Create new session from data. If session_id was also
                        present, use that as id, otherwise generate one.
            token:      Validate token and use session_id from it
                        to look up the session
            session_id: Look up session using session_id

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
            self.token = SessionReference.from_cookie(cookie_val, app_secret=self.app_secret)
        else:
            self.token = SessionReference.new(app_secret=self.app_secret)

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
        raise KeyError('Key {!r} not present in session'.format(key))

    def __setitem__(self, key, value):
        if self.whitelist and key not in self.whitelist:
            if self.raise_on_unknown:
                raise ValueError('Key {!r} not allowed in session'.format(key))
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
        Verify (and decrypt) session data read from Redis.

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
        return self._data


class SessionManager(object):
    """
    Factory objects that hold some configuration data and provide
    session objects.
    """

    def __init__(self, cfg, ttl=600, secret=None, whitelist=None, raise_on_unknown=False):
        """
        Constructor for SessionManager

        :param cfg: Redis connection settings dict
        :param ttl: The time to live for the sessions
        :param secret: token_key used to sign the keys associated
                       with the sessions
        :param whitelist: list of allowed keys for the sessions
        :param raise_on_unknown: Whether to raise an exception on an attempt
                                 to set a session session_id not in whitelist

        :type cfg: dict
        :type ttl: int
        :type secret: str
        :type whitelist: list
        :type raise_on_unknown: bool
        """
        self.pool = get_redis_pool(cfg)
        self.ttl = ttl
        self.secret = secret
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


def derive_key(app_key: str, session_key: str, usage: str, size: int) -> bytes:
    """
    Derive a cryptographic session_id for a specific usage from the app_key and the session_key.

    The app_key is a shared secret between all instances of this app (e.g. eduid-dashboard).
    The session_key is a randomized session_id unique to this session.

    :param app_key: Application shared session_id
    :param usage: 'sign' or 'encrypt' or something else
    :param session_key: Session unique session_id
    :param size: Size of key requested in bytes

    :return: Derived key
    """
    # the low number of rounds (3) is not important here - we use this to derive two keys
    # (different 'usage') from a single key which is comprised of a 256 bit app_key
    # (shared between instances), and a random session key of 128 bits.
    _salt = (usage + session_key).encode('utf-8')
    return hashlib.pbkdf2_hmac('sha256', app_key.encode('ascii'), _salt, 3, dklen=size)
