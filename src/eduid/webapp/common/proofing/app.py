import logging
from typing import Protocol, cast

from flask import current_app

from eduid.common.config.base import RootConfig
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.stats import AppStats
from eduid.userdb.logs.db import ProofingLog
from eduid.userdb.proofing.db import ProofingUserDB
from eduid.userdb.userdb import AmDB

__author__ = "lundberg"


class ProofingApp(Protocol):
    """
    The parts of a proofing webapp (eidas, bankid, samleid, freja_eid, ...) used by the shared proofing code.

    Members are read-only properties so that apps may declare more specific types (e.g. a ProofingUserDB subclass).

    This is a view of the request-serving app, not Flask's current_app: do not add Flask attributes here, import
    flask.current_app for those. It is not runtime_checkable, so do not use it with isinstance().
    """

    @property
    def conf(self) -> RootConfig: ...

    @property
    def logger(self) -> logging.Logger: ...

    @property
    def private_userdb(self) -> ProofingUserDB: ...

    @property
    def proofing_log(self) -> ProofingLog: ...

    @property
    def am_relay(self) -> AmRelay: ...

    @property
    def has_central_userdb(self) -> bool: ...

    @property
    def central_userdb(self) -> AmDB:
        """Raises RuntimeError for apps built with init_central_userdb=False, check has_central_userdb first."""
        ...

    @property
    def stats(self) -> AppStats: ...


current_proofing_app: ProofingApp = cast("ProofingApp", current_app)
