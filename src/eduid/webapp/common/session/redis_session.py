"""
Applications that need to store state in a distributed fashion can
use this module.

Basic usage:

    manager = SessionManager(redis_config, secret=app_secret)
    session = manager.get_session()
    session['foo'] = 'bar'
    session.commit()
    set_cookie(session.token.cookie_val)

Sessions are stored in a Redis backend (the currently deployed one
in eduID has three servers, one master and two slaves, and uses
Redis sentinel for high availability).

Since Redis does not do authorization, and to prevent data leakage
if the Redis server would get compromised, all data stored in Redis
is signed and encrypted. The current implementation uses the NaCl
crypto library to conveniently handle this.

To be able to load a session from Redis, one needs the application
specific key which is expected to be shared by all instances of an
application that needs to share session state, and the cookie from
the user since it contains a per-session secret key (derived from the
session_id).

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

from __future__ import annotations

import json
import logging
import typing
from collections.abc import Iterator, Mapping
from typing import Any, NamedTuple, cast

import nacl.encoding
import nacl.secret
import nacl.utils
import redis
from redis import sentinel

from eduid.common.config.base import RedisConfig
from eduid.common.misc.encoders import EduidJSONEncoder
from eduid.webapp.common.session.meta import SessionMeta

logger = logging.getLogger(__name__)

# Max WATCH/EXEC attempts in RedisEncryptedSession.commit() before giving up
_MAX_COMMIT_ATTEMPTS = 5


class SessionManager:
    """
    Factory objects that hold some configuration data and provide
    session objects.
    """

    def __init__(
        self,
        redis_config: RedisConfig,
        app_secret: str,
        ttl: int = 600,
        whitelist: list[str] | None = None,
        raise_on_unknown: bool = False,
    ) -> None:
        """
        Constructor for SessionManager

        :param redis_config: Redis connection settings
        :param app_secret: Shared secret for all instances of a particular application
        :param ttl: The time to live for the sessions
        :param whitelist: list of allowed keys for the sessions
        :param raise_on_unknown: Whether to raise an exception on an attempt
                                 to set a session session_id not in whitelist
        """
        self.pool = get_redis_pool(redis_config)
        self.ttl = ttl
        self.secret = app_secret
        # TODO: whitelist and raise_on_unknown is unused functionality. Remove?
        self.whitelist = whitelist
        self.raise_on_unknown = raise_on_unknown

    def _get_connection(self) -> redis.StrictRedis:
        """
        Get a Redis connection.

        Done in a separate function so that this class can be subclassed in test cases.
        """
        return redis.StrictRedis(connection_pool=self.pool)

    def get_session(self, meta: SessionMeta, new: bool) -> RedisEncryptedSession:
        """
        Create or fetch a session for the given token or data.

        :param cookie_val: the value of the session cookie, if any
        :param new: True if this is a new session

        :return: the session
        """
        conn = self._get_connection()

        res: RedisEncryptedSession = RedisEncryptedSession(
            conn,
            db_key=meta.session_id,
            encryption_key=meta.derive_key(self.secret, "nacl", nacl.secret.SecretBox.KEY_SIZE),
            ttl=self.ttl,
            whitelist=self.whitelist,
            raise_on_unknown=self.raise_on_unknown,
        )

        if new:
            logger.debug(f"Created new session {res}")
        elif not res.load_session():
            logger.warning(f"No existing session found for {res}")
            raise KeyError("Session not found using provided cookie")

        return res


def get_redis_pool(cfg: RedisConfig) -> sentinel.SentinelConnectionPool | redis.ConnectionPool:
    logger.debug(f"Redis configuration: {cfg}")
    if cfg.sentinel_hosts and cfg.sentinel_service_name:
        host_port = [(x, cfg.port) for x in cfg.sentinel_hosts]
        manager = sentinel.Sentinel(host_port, socket_timeout=0.1)  # type: ignore[no-untyped-call]
        return sentinel.SentinelConnectionPool(cfg.sentinel_service_name, manager)  # type: ignore[no-untyped-call]
    else:
        if not cfg.host:
            logger.error("Redis configuration without sentinel parameters does not have host")
            raise RuntimeError("Redis configuration incorrect")
        return redis.ConnectionPool(host=cfg.host, port=cfg.port, db=cfg.db)


class NoSessionDataFoundException(Exception):
    # TODO: This is never raised, which might be a bug since we have code to explicitly catch it
    pass


class SessionOutOfSync(Exception):
    pass


def _diff_paths(
    old: Mapping[str, Any], new: Mapping[str, Any], prefix: str = "", depth: int | None = None
) -> list[str]:
    """
    List the key paths that differ between two dicts, without including any values.

    :param old: The baseline
    :param new: The data to compare to the baseline
    :param prefix: Dotted path prefix of the dicts being compared
    :param depth: How many levels of nested dicts to recurse into, None for unlimited
    :returns: Descriptions like 'added idp.foo', 'removed bar' or 'changed idp.ts'
    """
    res: list[str] = []
    for k in sorted(old.keys() | new.keys()):
        path = f"{prefix}{k}"
        if k not in new:
            res.append(f"removed {path}")
        elif k not in old:
            res.append(f"added {path}")
        elif old[k] != new[k]:
            if (depth is None or depth > 1) and isinstance(old[k], dict) and isinstance(new[k], dict):
                res.extend(_diff_paths(old[k], new[k], prefix=f"{path}.", depth=None if depth is None else depth - 1))
            else:
                res.append(f"changed {path}")
    return res


class ConflictDescription(NamedTuple):
    """
    Key paths (no values) of a failed session commit, see RedisEncryptedSession.describe_conflict.

    theirs: changes made by the other writer since this instance loaded the session (empty if key_deleted)
    ours: changes this instance tried to write
    key_deleted: the session key no longer exists in the backend
    """

    theirs: list[str]
    ours: list[str]
    key_deleted: bool

    @property
    def other_removed_anything(self) -> bool:
        return self.key_deleted or any(c.startswith("removed ") for c in self.theirs)


class RedisEncryptedSession(typing.MutableMapping[str, Any]):
    """
    Session objects that keep their data in a redis db.
    """

    def __init__(
        self,
        conn: redis.StrictRedis,
        db_key: str,
        encryption_key: bytes,
        ttl: int,
        whitelist: list[str] | None = None,
        raise_on_unknown: bool = False,
    ) -> None:
        """
        Create an empty session object.

        If a user provided cookie is available, a subsequent call to `load_session` can be
        used to retrieve the session data.

        If whitelist is provided, no keys will be set unless they are
        explicitly listed in it; and if raise_on_unknown is True,
        a ValueError will be raised on every attempt to set a
        non-whitelisted key.

        :param conn: Redis connection instance
        :param app_secret: Application secret key used to sign the session_id associated
                       with the session
        :param ttl: The time to live for the session
        :param cookie_val: the token containing the session_id for the session
        :param whitelist: list of allowed keys for the sessions
        :param raise_on_unknown: Whether to raise an exception on an attempt
                                 to set a session key not in whitelist
        """
        self.conn = conn
        self.db_key = db_key
        self.encryption_key = encryption_key
        self.ttl = ttl
        self.whitelist = whitelist
        self.raise_on_unknown = raise_on_unknown
        # encrypted data loaded from redis, used to avoid clobbering concurrent updates to the session
        self._raw_data: bytes | None = None

        self.secret_box = nacl.secret.SecretBox(encryption_key)

        self._data: dict[str, Any] = {}

    def __str__(self) -> str:
        # Include hex(id(self)) for now to troubleshoot clobbered sessions
        return f"<{self.__class__.__name__} at {hex(id(self))}: db_key={self.short_id}>"

    def __getitem__(self, key: str) -> object:
        if key in self._data:
            return self._data[key]
        raise KeyError(f"Key {key!r} not present in session")

    def __setitem__(self, key: str, value: object) -> None:
        if self.whitelist and key not in self.whitelist:
            if self.raise_on_unknown:
                raise ValueError(f"Key {key!r} not allowed in session")
            return
        self._data[key] = value

    def __delitem__(self, key: str) -> None:
        del self._data[key]

    def __iter__(self) -> Iterator[str]:
        return self._data.__iter__()

    def __len__(self) -> int:
        return len(self._data)

    def __contains__(self, key: object) -> bool:
        return self._data.__contains__(key)

    @property
    def short_id(self) -> str:
        """Short version of db_key for use in logging"""
        return self.db_key[:8] + "..."

    def load_session(self) -> bool:
        logger.debug(f"Looking for session {self.short_id}")

        # Fetch session from session store (Redis). We remember the raw data and use it
        # when writing data back to Redis to detect if the session was updated by someone
        # else (in which case we abort).
        # TODO: conn.get returns ResponseT = Union[Awaitable, Any] - mypy doesn't like that
        self._raw_data = self.conn.get(self.db_key)  # type: ignore[assignment]
        if not self._raw_data:
            return False

        self._data = self.decrypt_data(self._raw_data)

        logger.debug(f"Loaded data from Redis[{self.short_id}]:\n{self._data!r}")
        return True

    def commit(self) -> None:
        """
        Persist the currently held data into the redis db.
        """
        data = self.encrypt_data(self._data)
        logger.debug(f"Committing session {self} to Redis with ttl {self.ttl} ({len(data)} bytes)")

        baseline = self._raw_data

        # Not using Redis.transaction(): it retries WatchError forever, and a peer's plain EXPIRE
        # (or a connection error while watching, which redis-py turns into WatchError) would hot-loop.
        for attempt in range(1, _MAX_COMMIT_ATTEMPTS + 1):
            with self.conn.pipeline() as pipe:
                try:
                    pipe.watch(self.db_key)  # type: ignore[no-untyped-call]
                    if baseline is not None:
                        # Pipeline is in immediate mode until multi() is called
                        _data_now = cast(bytes | None, pipe.get(self.db_key))
                        if _data_now != baseline:
                            raise SessionOutOfSync(f"The session {self} has been updated by someone else")
                    pipe.multi()
                    pipe.setex(self.db_key, self.ttl, data)
                    pipe.execute()
                except redis.WatchError:
                    logger.warning(f"Session {self} modified during commit, attempt {attempt}/{_MAX_COMMIT_ATTEMPTS}")
                    continue
            # The baseline only moves after a successful EXEC
            self._raw_data = data
            return
        raise SessionOutOfSync(f"The session {self} is contended")

    def describe_conflict(self) -> ConflictDescription:
        """
        Describe what differs after a failed commit, for diagnostics and for deciding if the loss is tolerable.

        :returns: What the other writer changed since load, and what this instance tried to change
        """
        baseline = self.decrypt_data(self._raw_data) if self._raw_data else {}
        raw_now = self.conn.get(self.db_key)
        key_deleted = not raw_now
        theirs = [] if key_deleted else _diff_paths(baseline, self.decrypt_data(cast(bytes, raw_now)))
        ours_data = json.loads(json.dumps(self._data, cls=EduidJSONEncoder))
        return ConflictDescription(theirs=theirs, ours=_diff_paths(baseline, ours_data), key_deleted=key_deleted)

    def encrypt_data(self, data_dict: Mapping[str, Any]) -> bytes:
        """
        Sign and encrypt data before storing it in Redis.

        :param data_dict: Data to be stored
        :return: serialized data
        """
        data_json = json.dumps(data_dict, cls=EduidJSONEncoder)
        logger.debug(f"Storing data in Redis[{self.short_id}]:\n{data_json}")
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        # Version data to make it easier to know how to decode it on reading
        versioned = {
            "v2": bytes(
                self.secret_box.encrypt(data_json.encode("ascii"), nonce, encoder=nacl.encoding.Base64Encoder)
            ).decode("ascii")
        }
        return bytes(json.dumps(versioned), "ascii")

    def decrypt_data(self, data_str: bytes | str) -> dict[str, Any]:
        """
        Decrypt and verify session data read from Redis.

        :param data_str: Data read from Redis
        :return: Parsed data as dict
        """
        versioned = json.loads(data_str)
        if "v2" in versioned:
            _data = self.secret_box.decrypt(versioned["v2"], encoder=nacl.encoding.Base64Encoder)
            decrypted = json.loads(_data)
            return cast(dict[str, Any], decrypted)

        logger.error(f"Unknown data retrieved from Redis[{self.short_id}]: {data_str!r}")
        raise ValueError("Unknown data retrieved from Redis")

    def clear(self) -> None:
        """
        Discard all data contained in the session.
        """
        self._data = {}
        self.conn.delete(self.db_key)
        self._raw_data = None

    def renew_ttl(self) -> None:
        """
        Restart the ttl countdown
        """
        self.conn.expire(self.db_key, self.ttl)

    def to_dict(self) -> dict[str, Any]:
        return dict(self._data)
