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
"""
Applications that need to store state in a distributed fashion can
use this module.

Basic usage:

    manager = SessionManager(redis_config, secret=app_secret)
    session = manager.get_session(data={})
    session['foo'] = 'bar'
    session.commit()
    set_cookie(session.token)

Sessions are stored in a Redis backend (the currently deployed one
in eduID has three servers, one master and two slaves, and uses
Redis sentinel for high availability).

Since Redis does not do authorization, and to prevent data leakage
if the Redis server would get compromized, all data stored in Redis
is signed and encrypted. The current implementation uses the NaCl
crypto library to conventiently handle this.

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

import hmac
import json
import hashlib
import collections
import redis
import redis.sentinel
import nacl.secret
import nacl.utils
import nacl.encoding
import base64
from saml2.saml import NameID

import logging
logger = logging.getLogger(__name__)

# Prepend an 'a' so we always have a valid NCName,
# needed by  pysaml2 for its session ids.
TOKEN_PREFIX = 'a'

HMAC_DIGEST_SIZE = 256 / 8
SESSION_KEY_BITS = 256


def get_redis_pool(cfg):
    port = cfg['REDIS_PORT']
    if cfg.get('REDIS_SENTINEL_HOSTS') and cfg.get('REDIS_SENTINEL_SERVICE_NAME'):
        _hosts = cfg['REDIS_SENTINEL_HOSTS']
        _name = cfg['REDIS_SENTINEL_SERVICE_NAME']
        host_port = [(x, port) for x in _hosts]
        manager = redis.sentinel.Sentinel(host_port, socket_timeout=0.1)
        pool = redis.sentinel.SentinelConnectionPool(_name, manager)
    else:
        db = cfg['REDIS_DB']
        host = cfg['REDIS_HOST']
        pool = redis.ConnectionPool(host=host, port=port, db=db)
    return pool


class NameIDEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, NameID):
            return str(obj)
        return json.JSONEncoder.default(self, obj)


class SessionManager(object):
    """
    Factory objects that hold some configuration data and provide
    session objects.
    """

    def __init__(self, cfg, ttl=600,
                 secret=None, whitelist=None, raise_on_unknown=False):
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

    def get_session(self, token=None, session_id=None, data=None):
        """
        Create or fetch a session for the given token or data.

        :param token: the token containing the session_id for the session
        :param session_id: the session_id to look for
        :param data: the data for the (new) session

        :type token: str | unicode | None
        :type session_id: bytes
        :type data: dict | None

        :return: the session
        :rtype: Session
        """
        conn = redis.StrictRedis(connection_pool=self.pool)
        return Session(conn, token=token, session_id=session_id, data=data,
                       secret=self.secret, ttl=self.ttl,
                       whitelist=self.whitelist,
                       raise_on_unknown=self.raise_on_unknown,
                       )


class Session(collections.MutableMapping):
    """
    Session objects that keep their data in a redis db.
    """

    def __init__(self, conn, token=None, session_id=None,
                 data=None, secret='', ttl=None,
                 whitelist=None, raise_on_unknown=False):
        """
        Retrive or create a session for the given token or data.

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
        :param token: the token containing the session_id for the session
        :param session_id: session_id for the session, if token is not provided
        :param data: the data for the (new) session
        :param ttl: The time to live for the session
        :param secret: Application secret key used to sign the session_id associated
                       with the session
        :param whitelist: list of allowed keys for the sessions
        :param raise_on_unknown: Whether to raise an exception on an attempt
                                 to set a session key not in whitelist

        :type conn: redis.StrictRedis
        :type token: str or None
        :type session_id: bytes
        :type data: dict or None
        :type secret: str
        :type ttl: int
        :type whitelist: list
        :type raise_on_unknown: bool
        """
        self.conn = conn
        self.ttl = ttl
        self.whitelist = whitelist
        self.raise_on_unknown = raise_on_unknown
        self.app_secret = secret

        _bin_session_id = self._init_token_and_session_id(token, session_id)
        _encrypted_data = None
        if data is None:
            if not (token or session_id):
                raise ValueError('Data must be provided when token/session_id is not provided')

            logger.debug('Looking for session using token {!r} or session_id {!r}'.format(token, session_id))

            # Fetch session from self.conn (Redis)
            _encrypted_data = self.conn.get(self.session_id)
            if not _encrypted_data:
                raise KeyError('Session not found: {!r}'.format(self.session_id))

        _nacl_key = derive_key(self.app_secret, _bin_session_id, b'nacl', nacl.secret.SecretBox.KEY_SIZE)
        self.nacl_box = nacl.secret.SecretBox(_nacl_key)

        if _encrypted_data:
            # Decode and verify data, need self.nacl_box to do this
            data = self.verify_data(_encrypted_data)

        if not isinstance(data, dict):
            # mostly convince pycharms introspection what type data is here
            raise ValueError('Data must be a dict, not {!s}'.format(type(data)))

        self._data = {}
        for k, v in data.items():
            if self.whitelist and k not in self.whitelist:
                if self.raise_on_unknown:
                    raise ValueError('Key {!r} not allowed in session'.format(k))
                continue
            self._data[k] = v

        logger.info('Created session with session_id %s and token %s' % (self.session_id, self.token))

    def _init_token_and_session_id(self, token, session_id):
        """
        Part of __init__(). Initializes self.token, self.token_key, self.session_id and
        returns the binary version of session_id.

        :param token: the token containing the session_id for the session
        :param session_id: session_id for the session, if token is not provided

        :return: Binary session id
        :rtype: bytes
        """
        if token:
            self.token = token
            _bin_session_id, _bin_signature = self.decode_token(token)
            self.token_key = derive_key(self.app_secret, _bin_session_id, b'hmac', HMAC_DIGEST_SIZE)
            if not verify_session_id(_bin_session_id, self.token_key, _bin_signature):
                raise ValueError('Token signature check failed')
        else:
            if not session_id:
                # Generate a random session_id
                session_id = nacl.utils.random(SESSION_KEY_BITS / 8)
            _bin_session_id = bytes(session_id)
            self.token_key = derive_key(self.app_secret, _bin_session_id, b'hmac', HMAC_DIGEST_SIZE)
            self.token = self.encode_token(_bin_session_id)
        self.session_id = _bin_session_id.encode('hex')
        return _bin_session_id

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
        data = self.sign_data(self._data)
        self.conn.setex(self.session_id, self.ttl, data)

    def encode_token(self, session_id):
        """
        Encode a session id and it's signature into a token that is stored
        in the users browser as a cookie.

        :param session_id: the session_id (Redis key)
        :type session_id: str | unicode

        :return: a token with the signed session_id
        :rtype: str | unicode
        """
        sig = sign_session_id(session_id, self.token_key)
        # The last byte ('x') is padding to prevent b32encode from adding an = at the end
        combined = base64.b32encode(session_id + sig + 'x')
        # Make sure token will be a valid NCName (pysaml2 requirement)
        while combined.endswith('='):
            combined = combined[:-1]
        return ''.join([TOKEN_PREFIX, combined])

    def decode_token(self, token):
        """
        Decode a token (token is what is stored in a cookie) into it's components.

        :param token: the token with the signed session_id
        :type token: str | unicode

        :return: the session_id and signature
        :rtype: str | unicode, str | unicode
        """
        #  the slicing is to remove a leading 'a' needed so we have a
        # valid NCName so pysaml2 doesn't complain when it uses the token as
        # session id.
        if not token.startswith(TOKEN_PREFIX):
            raise ValueError('Invalid token string {!r}'.format(token))
        val = token.strip('"')[len(TOKEN_PREFIX):]
        # Split the token into it's two parts - the session_id and the HMAC signature of it
        # (the last byte is ignored - it is padding to make b32encode not put an = at the end)
        _decoded = base64.b32decode(val)
        _bin_session_id, _bin_sig = _decoded[:HMAC_DIGEST_SIZE], _decoded[HMAC_DIGEST_SIZE:-1]
        return _bin_session_id, _bin_sig

    def sign_data(self, data_dict):
        """
        Sign (and encrypt) data before storing it in Redis.

        :param data_dict: Data to be stored
        :return: serialized data
        :rtype: str | unicode
        """
        # XXX remove this extra debug logging after burn-in period
        logger.debug('Storing v2 data in cache: {!r}'.format(data_dict))
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        # Version data to make it easier to know how to decode it on reading
        data_json = json.dumps(data_dict, cls=NameIDEncoder)
        versioned = {'v2': self.nacl_box.encrypt(data_json, nonce,
                                                 encoder = nacl.encoding.Base64Encoder)
                     }
        return json.dumps(versioned)

    def verify_data(self, data_str):
        """
        Verify (and decrypt) session data read from Redis.

        :param data_str: Data read from Redis
        :return: dict
        :rtype: dict
        """
        versioned = json.loads(data_str)
        if 'v1' in versioned:
            # XXX remove this extra debug logging after burn-in period
            logger.debug('Loaded v1 data from cache: {!r}'.format(versioned['v1']))
            return versioned['v1']
        if 'v2' in versioned:
            _data = self.nacl_box.decrypt(versioned['v2'],
                                          encoder = nacl.encoding.Base64Encoder)
            decrypted = json.loads(_data)
            logger.debug('Loaded v2 data from cache: {!r}'.format(decrypted))
            return decrypted

        logger.error('Unknown data retrieved from cache: {!r}'.format(data_str))
        raise ValueError('Unknown data retrieved from cache')

    def clear(self):
        """
        Discard all data contained in the session.
        """
        self._data = {}
        self.conn.delete(self.session_id)
        self.session_id = None
        self.token = None

    def renew_ttl(self):
        """
        Restart the ttl countdown
        """
        self.conn.expire(self.session_id, self.ttl)


def derive_key(app_key, session_key, usage, size):
    """
    Derive a cryptographic session_id for a specific usage from the app_key and the session_key.

    The app_key is a shared secret between all instances of this app (e.g. eduid-dashboard).
    The session_key is a randomized session_id unique to this session.

    :param app_key: Application shared session_id
    :param usage: 'sign' or 'encrypt' or something else
    :param session_key: Session unique session_id
    :param size: Size of key requested in bytes

    :type app_key: bytes
    :type usage: bytes
    :type session_key: bytes
    :type size: int

    :return: Derived key
    :rtype: bytes
    """
    # the low number of rounds (3) is not important here - we use this to derive two keys
    # (different 'usage') from a single key which is comprised of a 256 bit app_key
    # (shared between instances), and a random session key of 128 bits.
    return hashlib.pbkdf2_hmac('sha256', app_key, usage + session_key, 3, dklen = size)


def sign_session_id(session_id, signing_key):
    """
    Generate a HMAC signature of session_id using the session-unique signing key.

    :param session_id: Session id (Redis key)
    :param signing_key: Key for generating the signature

    :type session_id: bytes
    :type signing_key: bytes

    :return: Signature
    :rtype: bytes
    """
    return hmac.new(signing_key, session_id, digestmod=hashlib.sha256).digest()


def verify_session_id(session_id, signing_key, signature):
    """
    Verify the HMAC signature on a session_id using the session-unique signing key.

    :param session_id: Session id (Redis key)
    :param signing_key: Key for generating the signature
    :param signature: Signature of session_id

    :type session_id: bytes
    :type signing_key: bytes
    :type signature: bytes

    :return: True if the signature matches, false otherwise
    :rtype: bool
    """
    calculated_sig = hmac.new(signing_key, session_id, digestmod=hashlib.sha256).digest()

    # Avoid timing attacks, copied from Beaker https://beaker.readthedocs.org/
    invalid_bits = 0
    if len(calculated_sig) != len(signature):
        return None

    for a, b in zip(calculated_sig, signature):
        invalid_bits += a != b

    return bool(not invalid_bits)
