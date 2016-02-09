import uuid
import hmac
import json
import hashlib
import collections
import redis
import redis.sentinel

import logging
logger = logging.getLogger(__name__)

# Prepend an 'a' so we always have a valid NCName,
# needed by  pysaml2 for its session ids.
TOKEN_PREFIX = 'a'


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
        :param secret: secret used to sign the keys associated
                       with the sessions
        :param whitelist: list of allowed keys for the sessions
        :param raise_on_unknown: Whether to raise an exception on an attempt
                                 to set a session key not in whitelist

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
        self.secret =  secret
        self.whitelist = whitelist
        self.raise_on_unknown = raise_on_unknown

    def get_session(self, token=None, data=None):
        """
        Create a session for the given token or data.
        If the token param is provided, the data param is ignored,
        and the session data is retrieved from the db keyed by the key
        encapsulated in the token. If token is not provided, data must
        be provided, a new key and token are generated, and the provided
        data is stored in the db keyed by the newly generated key.

        :param token: the token containing the key for the session
        :param data: the data for the (new) session

        :type token: str or None
        :type data: dict or None

        :return: the session
        :rtype: Session
        """
        return Session(self.pool, token=token, data=data,
                       secret=self.secret, ttl=self.ttl,
                       whitelist=self.whitelist,
                       raise_on_unknown=self.raise_on_unknown)


class Session(collections.MutableMapping):
    """
    Session objects that keep their data in a redis db.
    """

    def __init__(self, pool, token=None, data=None, secret='', ttl=None,
                 whitelist=None, raise_on_unknown=False):
        """
        Create a session for the given token or data.

        If the token param is provided, the data param is ignored,
        and the session data is retrieved from the db keyed by the key
        encapsulated in the token. If token is not provided, data must
        be provided, a new key and token are generated, and the provided
        data is stored in the db keyed by the newly generated key.

        If whitelist is provided, no keys will be set unless they are
        explicitly listed in it; and if raise_on_unknown is True,
        a ValueError will be raised on every attempt to set a
        non-whitelisted key.

        :param pool: Pool from which to get the redis connection
        :param token: the token containing the key for the session
        :param data: the data for the (new) session
        :param ttl: The time to live for the session
        :param secret: secret used to sign the key associated
                       with the session
        :param whitelist: list of allowed keys for the sessions
        :param raise_on_unknown: Whether to raise an exception on an attempt
                                 to set a session key not in whitelist

        :type pool: redis.ConnectionPool
        :type token: str or None
        :type data: dict or None
        :type secret: str
        :type ttl: int
        :type whitelist: list
        :type raise_on_unknown: bool
        """
        self.conn = redis.StrictRedis(connection_pool=pool)
        self.ttl = ttl
        self.secret =  secret
        self.whitelist = whitelist
        self.raise_on_unknown = raise_on_unknown
        if token is None:
            if not isinstance(data, dict):
                # mostly convince pycharms introspection what type data is here
                raise ValueError('Data must be supplied when token is not')
            self.key = self.new_key()
            self.token = self.encode_token(self.key)
            self._data = {}
            if self.whitelist:
                if self.raise_on_unknown:
                    for k in data:
                        if k not in self.whitelist:
                            raise ValueError('key {!r} not allowed '
                                             'in session'.format(k))
                for k, v in data.items():
                    if k in self.whitelist:
                        self._data[k] = v
            else:
                for k, v in data.items():
                    self._data[k] = v
        else:
            self.token = token
            self.key = self.decode_token(token)
            data = self.conn.get(self.key)
            self._data = self.verify_data(data)
        logger.info('Created session with key %s and token %s' % (self.key, self.token))

    def __getitem__(self, key, default=None):
        if key in self._data:
            return self._data[key]
        elif default is not None:
            return default
        raise KeyError('key {!r} not present in session'.format(key))

    def __setitem__(self, key, value):
        if self.whitelist:
            if key not in self.whitelist:
                if self.raise_on_unknown:
                    raise ValueError('key {!r} not allowed '
                                     'in session'.format(key))
                else:
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
        self.conn.setex(self.key, self.ttl, data)

    def new_key(self):
        """
        Generate a new key
        """
        return uuid.uuid4().hex

    def encode_token(self, key):
        """
        Sign a key. Copied from Beaker https://beaker.readthedocs.org/

        :param key: the key to be signed
        :type key: str

        :return: a token with the signed key
        :rtype: str
        """
        sig = hmac.new(self.secret, key.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()
        # Prepend an 'a' so we always have a valid NCName, needed by
        # pysaml2 for its session ids.
        return ''.join([TOKEN_PREFIX, sig, key])

    def decode_token(self, token):
        """
        Check the signature of a key encapsulated in a token.
        Copied from Beaker https://beaker.readthedocs.org/

        :param token: the token with the signed key
        :type token: str

        :return: the unsigned key
        :rtype: str
        """
        #  the slicing is to remove a leading 'a' needed so we have a
        # valid NCName so pysaml2 doesn't complain when it uses the token as
        # session id.
        if not token.startswith(TOKEN_PREFIX):
            raise ValueError('Invalid token string {!r}'.format(token))
        val = token.strip('"')[len(TOKEN_PREFIX):]
        sig = hmac.new(self.secret, val[64:].encode('utf-8'), digestmod=hashlib.sha256).hexdigest()

        # Avoid timing attacks
        invalid_bits = 0
        input_sig = val[:64]
        if len(sig) != len(input_sig):
            return None

        for a, b in zip(sig, input_sig):
            invalid_bits += a != b

        if invalid_bits:
            return None
        else:
            return val[64:]

    def sign_data(self, data_dict):
        versioned = {1: data_dict}
        return json.dumps(versioned)

    def verify_data(self, data_str):
        versioned = json.loads(data_str)
        if 1 in versioned:
            return versioned[1]
        logger.error('Unknown data retrived from cache: {!r}'.format(data_str))
        raise ValueError('Unknown data retrieved from cache')

    def clear(self):
        """
        Discard all data contained in the session.
        """
        self._data = {}
        self.conn.delete(self.key)
        self.key = None
        self.token = None

    def renew_ttl(self):
        """
        Restart the ttl countdown
        """
        self.conn.expire(self.key, self.ttl)
