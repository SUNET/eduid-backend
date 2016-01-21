
import pickle
import uuid
import collections
from Crypto.Hash import HMAC, SHA as SHA1
import redis

import logging
logger = logging.getLogger(__name__)


class SessionManager(object):

    def __init__(self, host, port, db, whitelist=None, raise_on_unknown=False):
        '''
        '''
        self.pool = redis.ConnectionPool(host=host, port=port, db=db)
        self.whitelist = whitelist
        self.raise_on_unknown = raise_on_unknown

    def get_session(self, token=None, data=None, secret=None):
        '''
        '''
        return Session(self.pool, token=token, data=data,
                      secret=secret, whitelist=self.whitelist,
                      raise_on_unknown=self.raise_on_unknown)


class Session(collections.MutableMapping):

    def __init__(self, pool, token=None, data=None, secret='',
            whitelist=None, raise_on_unknown=False):
        '''
        '''
        self.conn = redis.Redis(connection_pool=pool)
        self.whitelist = whitelist
        self.raise_on_unknown = raise_on_unknown
        if token is None:
            self.key = self.new_key()
            self.token = self.encode(self.key, secret)
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
            self.key = self.decode(token, secret)
            data = self.conn.get(self.key)
            self._data = pickle.loads(data)
        logger.warn('Created session with key %s and token %s' % (self.key, self.token))

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
        '''
        data = pickle.dumps(self._data)
        self.conn.set(self.key, data)

    def new_key(self):
        '''
        '''
        return uuid.uuid4().hex

    def encode(self, key, secret):
        '''
        '''
        sig = HMAC.new(secret, key.encode('utf-8'), SHA1).hexdigest()
        return "%s%s" % (sig, key)

    def decode(self, token, secret):
        '''
        '''
        val = token.strip('"')
        sig = HMAC.new(secret, val[40:].encode('utf-8'), SHA1).hexdigest()

        # Avoid timing attacks
        invalid_bits = 0
        input_sig = val[:40]
        if len(sig) != len(input_sig):
            return None

        for a, b in zip(sig, input_sig):
            invalid_bits += a != b

        if invalid_bits:
            return None
        else:
            return val[40:]

    def clear(self):
        self._data = {}
        self.conn.delete(self.key)
        self.key = None
        self.token = None
