import re

import nacl.secret
import pytest
import redis.client
from pytest_mock import MockerFixture

from eduid.common.config.base import RedisConfig
from eduid.webapp.common.session.meta import SessionMeta
from eduid.webapp.common.session.redis_session import (
    _MAX_COMMIT_ATTEMPTS,
    ChangeKind,
    PathChange,
    RedisEncryptedSession,
    SessionManager,
    SessionOutOfSync,
    _diff_paths,
)
from eduid.webapp.common.session.testing import RedisTemporaryInstance


class TestSession:
    @pytest.fixture(autouse=True)
    def setup(self, redis_instance: RedisTemporaryInstance) -> None:
        self.redis_instance = redis_instance
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
        assert session2["foo"] == session1["foo"]

    def test_clear_session(self) -> None:
        """Test creating a session, clearing it and verifying it is gone"""
        _meta = SessionMeta.new(app_secret=self.manager.secret)

        session1 = self.manager.get_session(meta=_meta, new=True)
        session1["foo"] = "bar"
        session1.commit()

        # check the session is there now
        session2 = self.manager.get_session(meta=_meta, new=False)
        assert session2["foo"] == session1["foo"]

        # clear session
        session1.clear()

        # check that it is no longer there
        with pytest.raises(KeyError):
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
            assert re.search("^[a-z][a-zA-Z0-9.]+$", _meta.cookie_val)

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

    def _inject_write_on_first_multi(self, mocker: MockerFixture, db_key: str, injected: bytes) -> list[int]:
        """Make a concurrent write happen after the conflict check but before EXEC"""
        original_multi = redis.client.Pipeline.multi
        calls: list[int] = []

        def _multi(pipe: redis.client.Pipeline, *args: object, **kwargs: object) -> object:
            calls.append(1)
            if len(calls) == 1:
                self.redis_instance.conn.set(db_key, injected)
            return original_multi(pipe, *args, **kwargs)

        mocker.patch.object(redis.client.Pipeline, "multi", autospec=True, side_effect=_multi)
        return calls

    def test_commit_watch_retry_detects_conflict(self, mocker: MockerFixture) -> None:
        """A write between the conflict check and EXEC must be detected on the WATCH retry"""
        _meta = SessionMeta.new(app_secret=self.manager.secret)
        session1 = self.manager.get_session(meta=_meta, new=True)
        session1.commit()
        session2 = self.manager.get_session(meta=_meta, new=False)
        baseline = session2._raw_data
        assert baseline is not None

        other = self.manager.get_session(meta=_meta, new=False)
        other["other"] = "writer"
        injected = other.encrypt_data(other.to_dict())

        multi_calls = self._inject_write_on_first_multi(mocker, session2.db_key, injected)
        session2["mine"] = "data"
        with pytest.raises(SessionOutOfSync):
            session2.commit()

        assert self.redis_instance.conn.get(session2.db_key) == injected
        assert len(multi_calls) == 1
        assert session2._raw_data == baseline

    def test_commit_watch_retry_without_conflict(self, mocker: MockerFixture) -> None:
        """A spurious WatchError (same bytes written back) must be retried and then succeed"""
        _meta = SessionMeta.new(app_secret=self.manager.secret)
        session1 = self.manager.get_session(meta=_meta, new=True)
        session1.commit()
        session2 = self.manager.get_session(meta=_meta, new=False)
        baseline = session2._raw_data
        assert baseline is not None

        multi_calls = self._inject_write_on_first_multi(mocker, session2.db_key, baseline)
        session2["mine"] = "data"
        session2.commit()

        assert len(multi_calls) == 2
        now = self.redis_instance.conn.get(session2.db_key)
        assert now != baseline
        assert session2._raw_data == now
        assert self.manager.get_session(meta=_meta, new=False)["mine"] == "data"

    def test_commit_watch_contention_is_bounded(self, mocker: MockerFixture) -> None:
        """A peer EXPIRE on every attempt (value unchanged) must not cause an unbounded retry loop"""
        _meta = SessionMeta.new(app_secret=self.manager.secret)
        session1 = self.manager.get_session(meta=_meta, new=True)
        session1.commit()
        session2 = self.manager.get_session(meta=_meta, new=False)
        baseline = session2._raw_data
        assert baseline is not None

        original_multi = redis.client.Pipeline.multi
        calls: list[int] = []

        def _multi(pipe: redis.client.Pipeline, *args: object, **kwargs: object) -> object:
            calls.append(1)
            self.redis_instance.conn.expire(session2.db_key, 100)
            return original_multi(pipe, *args, **kwargs)

        mocker.patch.object(redis.client.Pipeline, "multi", autospec=True, side_effect=_multi)
        session2["mine"] = "data"
        with pytest.raises(SessionOutOfSync, match="contended"):
            session2.commit()

        assert len(calls) == _MAX_COMMIT_ATTEMPTS
        assert session2._raw_data == baseline
        assert self.redis_instance.conn.get(session2.db_key) == baseline

    def test_renew_ttl_watch_contention_is_bounded(self, mocker: MockerFixture) -> None:
        """A peer EXPIRE on every attempt (value unchanged) must not cause an unbounded retry loop"""
        _meta = SessionMeta.new(app_secret=self.manager.secret)
        session1 = self.manager.get_session(meta=_meta, new=True)
        session1.commit()
        session2 = self.manager.get_session(meta=_meta, new=False)
        baseline = session2._raw_data
        assert baseline is not None

        original_multi = redis.client.Pipeline.multi
        calls: list[int] = []

        def _multi(pipe: redis.client.Pipeline, *args: object, **kwargs: object) -> object:
            calls.append(1)
            self.redis_instance.conn.expire(session2.db_key, 100)
            return original_multi(pipe, *args, **kwargs)

        mocker.patch.object(redis.client.Pipeline, "multi", autospec=True, side_effect=_multi)
        with pytest.raises(SessionOutOfSync, match="contended"):
            session2.renew_ttl()

        assert len(calls) == _MAX_COMMIT_ATTEMPTS
        assert self.redis_instance.conn.get(session2.db_key) == baseline

    def test_renew_ttl_single_watch_collision_succeeds(self, mocker: MockerFixture) -> None:
        """One WatchError collision followed by an unchanged key renews the ttl"""
        _meta = SessionMeta.new(app_secret=self.manager.secret)
        session1 = self.manager.get_session(meta=_meta, new=True)
        session1.commit()
        session2 = self.manager.get_session(meta=_meta, new=False)
        baseline = session2._raw_data

        original_multi = redis.client.Pipeline.multi
        calls: list[int] = []

        def _multi(pipe: redis.client.Pipeline, *args: object, **kwargs: object) -> object:
            calls.append(1)
            if len(calls) == 1:
                self.redis_instance.conn.expire(session2.db_key, 100)
            return original_multi(pipe, *args, **kwargs)

        mocker.patch.object(redis.client.Pipeline, "multi", autospec=True, side_effect=_multi)
        session2.renew_ttl()

        assert len(calls) == 2
        assert self.redis_instance.conn.get(session2.db_key) == baseline
        assert self.redis_instance.conn.ttl(session2.db_key) == session2.ttl

    def test_describe_conflict(self) -> None:
        _meta = SessionMeta.new(app_secret=self.manager.secret)
        session1 = self.manager.get_session(meta=_meta, new=True)
        session1["keep"] = "x"
        session1.commit()
        session2 = self.manager.get_session(meta=_meta, new=False)
        session1["foo"] = "bar"
        session1.commit()
        session2["bar"] = "baz"
        with pytest.raises(SessionOutOfSync):
            session2.commit()
        conflict = session2.describe_conflict()
        assert conflict.theirs == [PathChange(ChangeKind.ADDED, "foo")]
        assert conflict.ours == [PathChange(ChangeKind.ADDED, "bar")]
        assert conflict.key_deleted is False
        assert conflict.other_removed_anything is False
        assert conflict.generation_changed is False

        session1.clear()
        conflict = session2.describe_conflict()
        assert conflict.theirs == []
        assert conflict.key_deleted is True
        assert conflict.other_removed_anything is True

        # Recreated without the old content shows as removals
        session1["new"] = "content"
        session1.commit()
        conflict = session2.describe_conflict()
        assert conflict.key_deleted is False
        assert conflict.theirs == [
            PathChange(ChangeKind.CHANGED, "_generation_"),
            PathChange(ChangeKind.REMOVED, "keep"),
            PathChange(ChangeKind.ADDED, "new"),
        ]
        assert conflict.other_removed_anything is True
        assert conflict.generation_changed is True


def test_diff_paths() -> None:
    old = {"a": 1, "b": {"x": 1, "y": {"deep": 1}}, "gone": 1}
    new = {"a": 2, "b": {"x": 1, "y": {"deep": 2}, "z": 3}, "added": 1}
    assert _diff_paths(old, new) == [
        PathChange(ChangeKind.CHANGED, "a"),
        PathChange(ChangeKind.ADDED, "added"),
        PathChange(ChangeKind.CHANGED, "b.y.deep"),
        PathChange(ChangeKind.ADDED, "b.z"),
        PathChange(ChangeKind.REMOVED, "gone"),
    ]
    assert str(PathChange(ChangeKind.CHANGED, "a")) == "changed a"
    assert _diff_paths(old, old) == []
