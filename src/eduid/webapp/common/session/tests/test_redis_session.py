from unittest import TestCase

import nacl
import pytest

from eduid.common.config.base import RedisConfig
from eduid.webapp.common.session.meta import SessionMeta
from eduid.webapp.common.session.redis_session import RedisEncryptedSession, SessionManager, SessionOutOfSync
from eduid.webapp.common.session.testing import RedisTemporaryInstance


class TestSession(TestCase):
    def setUp(self) -> None:
        self.redis_instance = RedisTemporaryInstance.get_instance()
        assert isinstance(self.redis_instance, RedisTemporaryInstance)
        _host, _port, _db = self.redis_instance.get_params()
        redis_cfg = RedisConfig(host=_host, port=_port, db=_db)
        self.manager = SessionManager(redis_cfg, app_secret="s3cr3t")

    def test_create_session(self) -> None:
        """Test creating a session and reading it back"""
        _meta = SessionMeta.new(app_secret=self.manager.secret)

        session1 = self.manager.get_session(meta=_meta, new=True)
        session1["foo"] = "bar"
        session1.commit()

        # read back session
        session2 = self.manager.get_session(meta=_meta, new=False)
        self.assertEqual(session2["foo"], session1["foo"])

    def test_clear_session(self) -> None:
        """Test creating a session, clearing it and verifying it is gone"""
        _meta = SessionMeta.new(app_secret=self.manager.secret)

        session1 = self.manager.get_session(meta=_meta, new=True)
        session1["foo"] = "bar"
        session1.commit()

        # check the session is there now
        session2 = self.manager.get_session(meta=_meta, new=False)
        self.assertEqual(session2["foo"], session1["foo"])

        # clear session
        session1.clear()

        # check that it is no longer there
        with self.assertRaises(KeyError):
            self.manager.get_session(meta=_meta, new=False)

    def test_decrypt_session(self) -> None:
        data = (
            '{"v2": "afNhp/JEYbt5Me/ain90IkVYrG3pYFRV018fOI+rT9B5E5Tf2fRac7inBH+SbkbF2dkfbWDD2nIWITI5y2ti73kZ'
            "gj1NqkFMMxnSW7cLVuIgUoVF2S+ZTzgF2pfUOyV5QNOkG2HzFE5BTF/G3C1yImPy0dz2rtAJUMtojjs7fFovnF6PGYm+8Lef"
            "IFcS2X9FQCZyc0o4k/QVKJNvxzeh8b7dcOcWYNg6ZiX8UyzH7NRfPPbTzexbFR70Jf+TCTensicVT19VXldl9cWMlQtb0Q4S"
            "pC1eS87290l1IfEbQY0/y8rn0BBoMXkSTAyLW4l7+NrppGdvl/MrayPofB4cNzZM0wjjK92UCG1Wpt4LPKFaGOalmVZAqV9L"
            "JFNxhp016L70jkibRBL61jLB5FSZ2joAF+MtQ8NWo2AuBe3QbYIP7tRpCA10NsN9lt/e4HbwYLmc/vwKDIxgzQqKxR6PkLHb"
            "amB0yznjlE9OOaK4at2oi8/i5IS7RggaSVrMeld6yG2WRq5b8KZh7vW6MyYthQlWa1y/M+bpMFPA/2LFDLeI3qzn5/0pW42c"
            "HizWY1xZ9JGp8z52NU7VB0ikLVLfmwCfYuv5hzTBZuADU/+HVcjDSoojpfG8fUX6y2lbcFz8aCzf4ZVGppnNg3PaNGmlet7u"
            "lHSPONsYR84L2miVx6CUmRF25CiX9BwgItfP8AQaV5+hdgK6Unjz0iGchyMOvkvc2jGdVp3NG5pSQBrtiIacIijsN85+2l+O"
            "664awCmf/QuXv1dLVdbutnGdF5FgFhwJ31BpFVD08Pe3iHTtbPjP9nt/EpwTA+dv6LdqspJkVN9/H0RZDBsv2OSsw3OKLGAe"
            "Fzlb1zwwLjeZQkOF6yroUbzj3i01r8MnD1Ad5NDqZvzdyOEsgUb5Wp3TqmYuMHPjhOWwrw+KlsELOHsSYwOf6KuTo2RNbxxx"
            'JvSQuHPagPP2ssIaTqy0mByRXK08xoewEKOoVy8daZjumnptnNnbH+nLqeDOB1m6pF15LLIj6dEcSw=="}'
        )
        app_secret = "supersecretkey"
        meta = SessionMeta.from_cookie(
            cookie_val="aG3KLGJZNK64ZPPT7GEV2BOADGF2HQIGOKFDRKZW5BPB54C6APJDDF7ABDY52QPPRVFQFITZW3"
            "TMGJTC6OFBA3L5G4J3V6HMFNFDK2Y3Y",
            app_secret=app_secret,
        )
        assert meta.session_id == "36d4b3272d57b997be7f312ba0b80331747820ce51471566dd0bc3de0bc07a46"

        session: RedisEncryptedSession = RedisEncryptedSession(
            conn=self.redis_instance.conn,
            db_key=meta.session_id,
            encryption_key=meta.derive_key(app_secret, "nacl", nacl.secret.SecretBox.KEY_SIZE),
            ttl=10,
        )
        decrypted = session.decrypt_data(data)
        assert decrypted["flag"] == "dirty session to force saving to redis 0.9806122964128207"

    def test_usable_token_encoding(self) -> None:
        """Pysaml uses the token as an XML NCName so it can't contain some characters."""
        for _i in range(1024):
            _meta = SessionMeta.new(app_secret=self.manager.secret)
            self.assertRegex(_meta.cookie_val, "^[a-z][a-zA-Z0-9.]+$")

    def test_clobbered_session(self) -> None:
        """Test what would happen if two requests are processed simultaneously"""
        _meta = SessionMeta.new(app_secret=self.manager.secret)
        session1 = self.manager.get_session(meta=_meta, new=True)
        session1.commit()
        session2 = self.manager.get_session(meta=_meta, new=False)
        session1["foo"] = "bar"
        session1.commit()

        session2["bar"] = "baz"
        with pytest.raises(SessionOutOfSync):
            session2.commit()

        session3 = self.manager.get_session(meta=_meta, new=False)
        assert session3["foo"] == "bar"
        assert "bar" not in session3
