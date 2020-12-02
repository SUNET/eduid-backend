#
# Copyright (c) 2018 SUNET
# Copyright (c) 2013, 2014, 2016, 2017 NORDUnet A/S
# Copyright 2012 Roland Hedberg. All rights reserved.
# All rights reserved.
#
# See the file eduid-IdP/LICENSE.txt for license statement.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#          Roland Hedberg
#
import logging
import time
import uuid
import warnings
from collections import deque
from threading import Lock
from typing import Any, Deque, Dict, List, Mapping, NewType, Optional, Tuple, Union, cast

from eduid_common.misc.timeutil import utc_now
from eduid_userdb.db import BaseDB

from eduid_webapp.idp.sso_session import SSOSession

_SHA1_HEXENCODED_SIZE = 160 // 8 * 2

# A distinct type for session ids
SSOSessionId = NewType('SSOSessionId', bytes)

# TODO: Rename to logger
module_logger = logging.getLogger(__name__)


class NoOpLock(object):
    """
    A No-op lock class, to avoid a lot of "if self.lock:" in code using locks.
    """

    def __init__(self) -> None:
        pass

    # noinspection PyUnusedLocal
    def acquire(self, _block: bool = True) -> bool:
        """
        Fake acquiring a lock.

        :param _block: boolean, whether to block or not (NO-OP in this implementation)
        """
        return True

    def release(self) -> None:
        """
        Fake releasing a lock.
        """
        pass


class ExpiringCacheMem:
    """
    Simplistic implementation of a cache that removes entrys as they become too old.

    This implementation invokes garbage collecting on every addition of data. This
    is believed to be a pragmatic approach for small to medium sites. For a large
    site with e.g. load balancers causing uneven traffic patterns, this might not
    work that well and the use of an external cache such as memcache is recommended.

    :param name: name of cache as string, only used for debugging
    :param logger: logging logger instance
    :param ttl: data time to live in this cache, as seconds (integer)
    :param lock: threading.Lock compatible locking instance
    """

    def __init__(self, name: str, logger: Optional[logging.Logger], ttl: int, lock: Optional[Lock] = None):
        self.logger = logger
        self.ttl = ttl
        self.name = name
        self._data: Dict[SSOSessionId, Any] = {}
        self._ages: Deque[Tuple[float, SSOSessionId]] = deque()
        self.lock = lock
        if self.lock is None:
            self.lock = cast(Lock, NoOpLock())  # intentionally lie to mypy

        if self.logger is not None:
            warnings.warn('Object logger deprecated, using module_logger', DeprecationWarning)

    def add(self, key: SSOSessionId, info: Any, now: Optional[int] = None) -> None:
        """
        Add entry to the cache.

        Ability to supply current time is only meant for test cases!

        :param key: Lookup key for entry
        :param info: Value to be stored for 'key'
        :param now: Current time - do not use unless testing!
        """
        self._data[key] = info
        # record when this entry shall be purged
        _now = now
        if _now is None:
            _now = int(time.time())
        self._ages.append((_now, key))
        self._purge_expired(_now - self.ttl)

    def _purge_expired(self, timestamp: int) -> None:
        """
        Purge expired records.

        :param timestamp: Purge any entrys older than this (integer)
        """
        if not self.lock or not self.lock.acquire(False):
            # if we don't get the lock, don't worry about it and just skip purging
            return None
        try:
            # purge any expired records. self._ages have the _data entries listed with oldest first.
            while True:
                try:
                    (_exp_ts, _exp_key) = self._ages.popleft()
                except IndexError:
                    break
                if _exp_ts > timestamp:
                    # entry not expired - reinsert in queue and end purging
                    self._ages.appendleft((_exp_ts, _exp_key))
                    break
                module_logger.debug(
                    'Purged {!s} cache entry {!s} seconds over limit : {!s}'.format(
                        self.name, timestamp - _exp_ts, _exp_key
                    )
                )
                self.delete(_exp_key)
        finally:
            self.lock.release()

    def get(self, key: SSOSessionId) -> Optional[Mapping[str, Any]]:
        """
        Fetch data from cache based on `key'.

        :param key: hash key to use for lookup
        :returns: Any data found matching `key', or None.
        """
        return self._data.get(key)

    def update(self, key: SSOSessionId, info: Any) -> None:
        """
        Update an entry in the cache.

        :param key: Lookup key for entry
        :param info: Value to be stored for 'key'
        :return: None
        """
        self._data[key] = info

    def delete(self, key: SSOSessionId) -> bool:
        """
        Delete an item from the cache.

        :param key: hash key to delete
        :return: True on success
        """
        try:
            del self._data[key]
            return True
        except KeyError:
            module_logger.debug('Failed deleting key {!r} from {!s} cache (entry did not exist)'.format(key, self.name))
        return False

    def items(self) -> Any:
        """
        Return all items from cache.
        """
        return self._data


class SSOSessionCache(BaseDB):
    def __init__(self, db_uri: str, ttl: int, db_name: str = 'eduid_idp', collection: str = 'sso_sessions'):
        super().__init__(db_uri, db_name, collection=collection)

        # Remove messages older than created_ts + ttl
        indexes = {
            'auto-discard': {'key': [('created_ts', 1)], 'expireAfterSeconds': ttl},
        }
        self.setup_indexes(indexes)

    def remove_session(self, sid: SSOSessionId) -> Union[int, bool]:
        """
        Remove entrys when SLO is executed.

        :param sid: Session identifier as string
        :return: False on failure
        """
        res = self._coll.remove({'session_id': sid}, w='majority')
        try:
            return int(res['n'])  # number of deleted records
        except (KeyError, TypeError):
            module_logger.warning(f'Remove session {repr(sid)} failed, result: {repr(res)}')
            return False

    def add_session(self, username: str, session: SSOSession) -> SSOSessionId:
        """
        Add a new SSO session to the cache.

        The mapping of uid -> user (and data) is used when a user visits another SP before
        the SSO session expires, and the mapping of user -> uid is used if the user requests
        logout (SLO).

        :param username: Username as string
        :param session: Session to add
        :return: Unique session identifier
        """
        _sid = self._create_session_id()
        _doc = {
            'session_id': _sid,
            'username': username,
            'data': session.to_dict(),
            'created_ts': utc_now(),
        }
        self._coll.insert(_doc)
        return _sid

    def update_session(self, username: str, data: Mapping[str, Any]) -> None:
        """
        Update a SSO session in the cache.

        :param username: Username as string
        :param data: opaque, should be SSOSession converted to dict()
        """
        raise NotImplementedError()

    def get_session(self, sid: SSOSessionId) -> Optional[SSOSession]:
        """
        Lookup an SSO session using the session id (same `sid' previously used with add_session).

        :param sid: Unique session identifier as string
        :return: The session, if found
        """
        try:
            res = self._coll.find_one({'session_id': sid})
        except KeyError:
            module_logger.debug(f'Failed looking up SSO session with id={repr(sid)}')
            raise
        if not res:
            return None

        # TODO: Make from_dict a classmethod on SSOSession
        from eduid_webapp.idp.sso_session import from_dict as ssosession_from_dict

        return ssosession_from_dict(res['data'])

    def get_sessions_for_user(self, username: str) -> List[SSOSessionId]:
        """
        Lookup all SSO session ids for a given username. Used in SLO with SOAP binding.

        :param username: The username to look for

        :return: A list with zero or more SSO session ids
        """
        # TODO: Change this function to return sessions - just have to make the SSOSession objects
        #       include the session_id first (so that Logout can call remove_session()).
        res = []
        entrys = self._coll.find({'username': username})
        for this in entrys:
            res.append(this['session_id'])
        return res

    def _create_session_id(self) -> SSOSessionId:
        """
        Create a unique value suitable for use as session identifier.

        The uniqueness and unability to guess is security critical!
        :return: session_id as bytes (to match what cookie decoding yields)
        """
        return SSOSessionId(bytes(str(uuid.uuid4()), 'ascii'))
