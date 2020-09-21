import time
from typing import Any, Mapping, Optional, cast
from unittest import TestCase

import redis

from eduid_common.session.redis_session import RedisEncryptedSession, SessionManager


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
        self, cookie_val: Optional[str] = None, data: Optional[Mapping[str, Any]] = None,
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

    def test_decrypt_session(self):
        data = (
            '{"v2": "afNhp/JEYbt5Me/ain90IkVYrG3pYFRV018fOI+rT9B5E5Tf2fRac7inBH+SbkbF2dkfbWDD2nIWITI5y2ti73kZ'
            'gj1NqkFMMxnSW7cLVuIgUoVF2S+ZTzgF2pfUOyV5QNOkG2HzFE5BTF/G3C1yImPy0dz2rtAJUMtojjs7fFovnF6PGYm+8Lef'
            'IFcS2X9FQCZyc0o4k/QVKJNvxzeh8b7dcOcWYNg6ZiX8UyzH7NRfPPbTzexbFR70Jf+TCTensicVT19VXldl9cWMlQtb0Q4S'
            'pC1eS87290l1IfEbQY0/y8rn0BBoMXkSTAyLW4l7+NrppGdvl/MrayPofB4cNzZM0wjjK92UCG1Wpt4LPKFaGOalmVZAqV9L'
            'JFNxhp016L70jkibRBL61jLB5FSZ2joAF+MtQ8NWo2AuBe3QbYIP7tRpCA10NsN9lt/e4HbwYLmc/vwKDIxgzQqKxR6PkLHb'
            'amB0yznjlE9OOaK4at2oi8/i5IS7RggaSVrMeld6yG2WRq5b8KZh7vW6MyYthQlWa1y/M+bpMFPA/2LFDLeI3qzn5/0pW42c'
            'HizWY1xZ9JGp8z52NU7VB0ikLVLfmwCfYuv5hzTBZuADU/+HVcjDSoojpfG8fUX6y2lbcFz8aCzf4ZVGppnNg3PaNGmlet7u'
            'lHSPONsYR84L2miVx6CUmRF25CiX9BwgItfP8AQaV5+hdgK6Unjz0iGchyMOvkvc2jGdVp3NG5pSQBrtiIacIijsN85+2l+O'
            '664awCmf/QuXv1dLVdbutnGdF5FgFhwJ31BpFVD08Pe3iHTtbPjP9nt/EpwTA+dv6LdqspJkVN9/H0RZDBsv2OSsw3OKLGAe'
            'Fzlb1zwwLjeZQkOF6yroUbzj3i01r8MnD1Ad5NDqZvzdyOEsgUb5Wp3TqmYuMHPjhOWwrw+KlsELOHsSYwOf6KuTo2RNbxxx'
            'JvSQuHPagPP2ssIaTqy0mByRXK08xoewEKOoVy8daZjumnptnNnbH+nLqeDOB1m6pF15LLIj6dEcSw=="}'
        )
        session = RedisEncryptedSession(
            conn=None,  # type: ignore
            app_secret='supersecretkey',
            ttl=3600,
            cookie_val='aG3KLGJZNK64ZPPT7GEV2BOADGF2HQIGOKFDRKZW5BPB54C6APJDDF7ABDY52QPPRVFQFITZW3'
            'TMGJTC6OFBA3L5G4J3V6HMFNFDK2Y3Y',
        )
        assert session.token.session_id == '36d4b3272d57b997be7f312ba0b80331747820ce51471566dd0bc3de0bc07a46'
        decrypted = session.decrypt_data(data)
        assert decrypted['flag'] == 'dirty session to force saving to redis 0.9806122964128207'

    def test_usable_token_encoding(self):
        """ Pysaml uses the token as an XML NCName so it can't contain some characters. """
        for i in range(1024):
            session = self.mgr.get_session(data={'foo': 'bar'})
            self.assertRegex(session.token.cookie_val, '^[a-z][a-zA-Z0-9.]+$')
