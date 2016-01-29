
import uuid
import collections
from Crypto.Hash import HMAC, SHA256
import redis

import logging
logger = logging.getLogger(__name__)


class NoopSerializer(object):
    '''
    dummy serializer that does nothing.
    '''

    def dumps(self, data):
        return data

    def loads(self, data):
        return data


class SessionManager(object):
    '''
    Factory objects that hold some configuration data and provide
    session objects.
    '''

    def __init__(self, host, port, db, serializer=NoopSerializer(),
            ttl=600, secret=None, whitelist=None, raise_on_unknown=False):
        '''
        Constructor for SessionManager

        :param host: hostname of redis server
        :type host: str
        :param port: port of the redis server
        :type port: int
        :param db: redis database
        :type db: int
        :param serializer: serializer (to str) object 
                           with dumps and loads methods
        :type serializer: object
        :param ttl: The time to live for the sessions
        :type ttl: int
        :param secret: secret used to sign the keys associated
                       with the sessions
        :type secret: str
        :param whitelist: list of allowed keys for the sessions
        :type whitelist: list
        :param raise_on_unknown: Whether to raise an exception on an attempt
                                 to set a session key not in whitelist
        :type raise_on_unknown: bool
        '''
        self.host = host
        self.port = port
        self.db = db
        self.pool = redis.ConnectionPool(host=host, port=port, db=db)
        self.serializer = serializer
        self.ttl = ttl
        self.secret =  secret
        self.whitelist = whitelist
        self.raise_on_unknown = raise_on_unknown

    def get_session(self, token=None, data=None):
        '''
        Create a session for the given token or data.
        If the token param is provided, the data param is ignored,
        and the session data is retrieved from the db keyed by the key
        encapsulated in the token. If token is not provided, data must
        be provided, a new key and token are generated, and the provided
        data is stored in the db keyed by the newly generated key.

        :param token: the token containing the key for the session
        :type token: str or None
        :param data: the data for the (new) session
        :type data: dict or None

        :return: the session
        :rtype: Session
        '''
        return Session(self.pool, token=token, data=data,
                      secret=self.secret, serializer=self.serializer,
                      ttl=self.ttl, whitelist=self.whitelist,
                      raise_on_unknown=self.raise_on_unknown)


class Session(collections.MutableMapping):
    '''
    Session objects that keep their data in a redis db.
    '''

    def __init__(self, pool, token=None, data=None,
            secret='', serializer=NoopSerializer(), ttl=None,
            whitelist=None, raise_on_unknown=False):
        '''
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
        :type pool: redis.ConnectionPool
        :param token: the token containing the key for the session
        :type token: str or None
        :param data: the data for the (new) session
        :type data: dict or None
        :param serializer: serializer (to str) object 
                           with dumps and loads methods
        :type serializer: object
        :param ttl: The time to live for the session
        :type ttl: int
        :param secret: secret used to sign the key associated
                       with the session
        :type secret: str
        :param whitelist: list of allowed keys for the sessions
        :type whitelist: list
        :param raise_on_unknown: Whether to raise an exception on an attempt
                                 to set a session key not in whitelist
        :type raise_on_unknown: bool
        '''
        self.conn = redis.StrictRedis(connection_pool=pool)
        self.serializer = serializer
        self.ttl = ttl
        self.secret =  secret
        self.whitelist = whitelist
        self.raise_on_unknown = raise_on_unknown
        if token is None:
            self.key = self.new_key()
            self.token = self.encode(self.key)
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
            self.key = self.decode(token)
            data = self.conn.get(self.key)
            self._data = self.serializer.loads(data)
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
        '''
        Persist the currently held data into the redis db.
        '''
        data = self.serializer.dumps(self._data)
        self.conn.setex(self.key, self.ttl, data)

    def new_key(self):
        '''
        Generate a new key
        '''
        return uuid.uuid4().hex

    def encode(self, key):
        '''
        Sign a key. Copied from Beaker https://beaker.readthedocs.org/

        :param key: the key to be signed
        :type key: str

        :return: a token with the signed key
        :rtype: str
        '''
        sig = HMAC.new(self.secret, key.encode('utf-8'), SHA256).hexdigest()
        # Prepend an 'a' so we always have a valid NCName, needed by
        # pysaml2 for its session ids.
        return "a%s%s" % (sig, key)

    def decode(self, token):
        '''
        Check the signature of a key encapsulated in a token.
        Copied from Beaker https://beaker.readthedocs.org/

        :param token: the token with the signed key
        :type token: str

        :return: the unsigned key
        :rtype: str
        '''
        #  the slicing is to remove a leading 'a' needed so we have a
        # valid NCName so pysaml2 doesn't complain when it uses the token as
        # session id.
        val = token.strip('"')[1:]
        sig = HMAC.new(self.secret, val[64:].encode('utf-8'), SHA256).hexdigest()

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

    def clear(self):
        '''
        Discard all data contained in the session.
        '''
        self._data = {}
        self.conn.delete(self.key)
        self.key = None
        self.token = None

    def renew_ttl(self):
        '''
        Restart the ttl countdown
        '''
        self.conn.expire(self.key, self.ttl)
