import hmac
import json
import bcrypt
import hashlib
import collections
import redis
import redis.sentinel
import nacl.secret
import nacl.utils
import nacl.encoding

import logging
logger = logging.getLogger(__name__)

# Prepend an 'a' so we always have a valid NCName,
# needed by  pysaml2 for its session ids.
TOKEN_PREFIX = 'a'

HMAC_DIGEST_SIZE = 256 / 8


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
        port = cfg['redis_port']
        if cfg.get('redis_sentinel_hosts') and cfg.get('redis_sentinel_service_name'):
            _hosts = cfg['redis_sentinel_hosts']
            _name = cfg['redis_sentinel_service_name']
            host_port = [(x, port) for x in _hosts]
            manager = redis.sentinel.Sentinel(host_port, socket_timeout=0.1)
            self.pool = redis.sentinel.SentinelConnectionPool(_name, manager)
        else:
            db = cfg['redis_db']
            host = cfg['redis_host']
            self.pool = redis.ConnectionPool(host=host, port=port, db=db)
        self.ttl = ttl
        self.secret = secret
        self.whitelist = whitelist
        self.raise_on_unknown = raise_on_unknown

    def get_session(self, token=None, data=None):
        """
        Create a session for the given token or data.
        If the token param is provided, the data param is ignored,
        and the session data is retrieved from the db keyed by the session_id
        encapsulated in the token. If token is not provided, data must
        be provided, a new session_id and token are generated, and the provided
        data is stored in the db keyed by the newly generated session_id.

        :param token: the token containing the session_id for the session
        :param data: the data for the (new) session

        :type token: str or None
        :type data: dict or None

        :return: the session
        :rtype: Session
        """
        conn = redis.StrictRedis(connection_pool=self.pool)
        return Session(conn, token=token, data=data,
                       secret=self.secret, ttl=self.ttl,
                       whitelist=self.whitelist,
                       raise_on_unknown=self.raise_on_unknown)


class Session(collections.MutableMapping):
    """
    Session objects that keep their data in a redis db.
    """

    def __init__(self, conn, token=None, data=None, secret='', ttl=None,
                 whitelist=None, raise_on_unknown=False):
        """
        Create a session for the given token or data.

        If the token param is provided, the data param is ignored,
        and the session data is retrieved from the db keyed by the session_id
        encapsulated in the token. If token is not provided, data must
        be provided, a new session_id and token are generated, and the provided
        data is stored in the db keyed by the newly generated session_id.

        If whitelist is provided, no keys will be set unless they are
        explicitly listed in it; and if raise_on_unknown is True,
        a ValueError will be raised on every attempt to set a
        non-whitelisted session_id.

        :param conn: Redis connection instance
        :param token: the token containing the session_id for the session
        :param data: the data for the (new) session
        :param ttl: The time to live for the session
        :param secret: token_key used to sign the session_id associated
                       with the session
        :param whitelist: list of allowed keys for the sessions
        :param raise_on_unknown: Whether to raise an exception on an attempt
                                 to set a session session_id not in whitelist

        :type conn: redis.StrictRedis
        :type token: str or None
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
        if token is None:
            if not isinstance(data, dict):
                # mostly convince pycharms introspection what type data is here
                raise ValueError('Data must be supplied when token is not')
            _bin_session_id = nacl.utils.random(256 / 8)
            self.token_key = _derive_key(self.app_secret, _bin_session_id, 'hmac', HMAC_DIGEST_SIZE)
            _nacl_key = _derive_key(self.app_secret, _bin_session_id, 'nacl', nacl.secret.SecretBox.KEY_SIZE)
            self.nacl_box = nacl.secret.SecretBox(_nacl_key)
            self.token = self.encode_token(_bin_session_id)
            self.session_id = _bin_session_id.encode('hex')
            self._data = {}

            for k, v in data.items():
                if self.whitelist and k not in self.whitelist:
                    if self.raise_on_unknown:
                        raise ValueError('Key {!r} not allowed in session'.format(k))
                    continue
                self._data[k] = v
        else:
            self.token = token
            _bin_session_id, _bin_signature = self.decode_token(token)
            self.token_key = _derive_key(self.app_secret, _bin_session_id, 'hmac', HMAC_DIGEST_SIZE)
            self.session_id = _bin_session_id.encode('hex')
            if not verify_session_id(_bin_session_id, self.token_key, _bin_signature):
                raise ValueError('Token signature check failed')
            data = self.conn.get(self.session_id)
            if not data:
                raise KeyError('Session not found: {!r}'.format(self.session_id))
            _nacl_key = _derive_key(self.app_secret, _bin_session_id, 'nacl', nacl.secret.SecretBox.KEY_SIZE)
            self.nacl_box = nacl.secret.SecretBox(_nacl_key)
            self._data = self.verify_data(data)
        logger.info('Created session with session_id %s and token %s' % (self.session_id, self.token))

    def __getitem__(self, key, default=None):
        if key in self._data:
            return self._data[key]
        elif default is not None:
            return default
        raise KeyError('session_id {!r} not present in session'.format(key))

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
        # Prepend an 'a' so we always have a valid NCName, needed by
        # pysaml2 for its session ids.
        encoder = nacl.encoding.Base64Encoder()
        combined = encoder.encode('.'.join([session_id, sig]))
        # equal-signs are disallowed in NCNames
        while combined[-1] == '=':
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
        decoder = nacl.encoding.Base64Encoder()
        # the == was removed in encode_token() to keep it a valid NCName
        _parts = decoder.decode(val + '==').split('.')
        _bin_session_id = _parts[0]
        _bin_sig = _parts[1]
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
        versioned = {'v2': self.nacl_box.encrypt(json.dumps(data_dict), nonce,
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


def _derive_key(app_key, session_key, usage, size):
    """
    Derive a cryptographic session_id for a specific usage from the app_key and the session_key.

    The app_key is a shared secret between all instances of this app (e.g. eduid-dashboard).
    The session_key is a randomized session_id unique to this session.

    :param app_key: Application shared session_id
    :param usage: 'sign' or 'encrypt' or something else
    :param session_key: Session unique session_id
    :param size: Size of key requested in bytes

    :return: session_id as raw bytes
    :rtype: str | unicode
    """
    return bcrypt.kdf(app_key, ''.join([usage, session_key]), size, 1)


def sign_session_id(session_id, signing_key):
    """
    Generate a HMAC signature of session_id using the session-unique signing key.

    :param session_id: Session id (Redis key)
    :param signing_key: Key for generating the signature

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
