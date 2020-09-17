import time
from typing import Optional, cast
from unittest import TestCase

import redis

from eduid_common.session.redis_session import RedisEncryptedSession, SessionReference, derive_key


class FakeRedisConn(object):
    def __init__(self):
        self._data = {}

    def setex(self, key, ttl, data):
        self._data[key] = {
            'expire': int(time.time()) + ttl,
            'data': data,
        }

    def get(self, key):
        res = self._data.get(key)
        if not res:
            return None
        return res['data']

    def delete(self, key):
        if key in self._data:
            del self._data[key]


class TestSession(TestCase):
    def setUp(self):
        self.conn = cast(redis.StrictRedis, FakeRedisConn())
        try:
            # Detect too old Python (like on CI) and skip tests
            derive_key('unittest', 'session', 'test', 16)
        except AttributeError:
            self.skipTest('Python hashlib does not contain pbkdf2')

    def test_create_session(self):
        """ Test creating a session and reading it back """
        session1 = self._get_session(data={'foo': 'bar'})
        session1.commit()

        # read back session
        session2 = self._get_session(token=session1.token)
        self.assertEqual(session2['foo'], session1['foo'])

    def test_get_empty_session(self):
        """Test getting an empty session"""

        # The ValueError is caught in the SessionFactory and triggers
        # the creation of a new, empty session.
        with self.assertRaises(ValueError):
            self._get_session(token=None, data=None)

    def test_clear_session(self):
        """ Test creating a session, clearing it and verifying it is gone """
        session1 = self._get_session(data={'foo': 'bar'})
        session1.commit()

        token = session1.token

        # check the session is there now
        session2 = self._get_session(token=token)
        self.assertEqual(session2['foo'], session1['foo'])

        # clear session
        session1.clear()

        # check that it is no longer there
        with self.assertRaises(KeyError):
            self._get_session(token=token)

    def test_usable_token_encoding(self):
        """ Pysaml uses the token as an XML NCName so it can't contain some characters. """
        for i in range(1024):
            session = self._get_session(data={'foo': 'bar'})
            self.assertRegex(session.token.cookie_val, '^[a-z][a-zA-Z0-9.]+$')

    def _get_session(
        self,
        token: Optional[SessionReference] = None,
        data=None,
        secret='s3cr3t',
        ttl=10,
        whitelist=None,
        raise_on_unknown=False,
    ):
        session = RedisEncryptedSession(
            self.conn,
            token=None if token is None else token.cookie_val,
            data=data,
            secret=secret,
            ttl=ttl,
            whitelist=whitelist,
            raise_on_unknown=raise_on_unknown,
        )
        return session
