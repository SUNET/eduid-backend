import time
from typing import Any, Mapping, Optional, cast
from unittest import TestCase

import redis

from eduid_common.session.redis_session import RedisEncryptedSession, SessionManager, derive_key


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


class FakeSessionManager(SessionManager):

    def __init__(self):
        self.secret = 's3cr3t'
        self.ttl = 10
        self.whitelist = []
        self.raise_on_unknown = False
        self.conn = cast(redis.StrictRedis, FakeRedisConn())

    def _get_connection(self) -> redis.StrictRedis:
        return self.conn

    def get_session(
        self,
        cookie_val: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
    ):
        session = super().get_session(cookie_val=cookie_val)
        # Add test data into the session
        if data is not None:
            for k, v in data.items():
                session[k] = v
        return session


class TestSession(TestCase):
    def setUp(self):
        self.mgr = FakeSessionManager()

    def test_create_session(self):
        """ Test creating a session and reading it back """
        session1 = self.mgr.get_session(data={'foo': 'bar'})
        session1.commit()

        # read back session
        session2 = self.mgr.get_session(cookie_val=session1.token.cookie_val)
        self.assertEqual(session2['foo'], session1['foo'])

    def test_clear_session(self):
        """ Test creating a session, clearing it and verifying it is gone """
        session1 = self.mgr.get_session(data={'foo': 'bar'})
        session1.commit()

        cookie_val = session1.token.cookie_val

        # check the session is there now
        session2 = self.mgr.get_session(cookie_val=cookie_val)
        self.assertEqual(session2['foo'], session1['foo'])

        # clear session
        session1.clear()

        # check that it is no longer there
        with self.assertRaises(KeyError):
            self.mgr.get_session(cookie_val=cookie_val)

    def test_usable_token_encoding(self):
        """ Pysaml uses the token as an XML NCName so it can't contain some characters. """
        for i in range(1024):
            session = self.mgr.get_session(data={'foo': 'bar'})
            self.assertRegex(session.token.cookie_val, '^[a-z][a-zA-Z0-9.]+$')
