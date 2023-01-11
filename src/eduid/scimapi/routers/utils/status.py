import sys
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
from collections.abc import Mapping

from fastapi import Response

from eduid.scimapi.context_request import ContextRequest

__author__ = "lundberg"


@dataclass
class SimpleCacheItem:
    expire_time: datetime
    data: Mapping


@dataclass
class FailCountItem:
    first_failure: datetime = field(repr=False)
    restart_at: Optional[datetime] = None
    restart_interval: Optional[int] = None
    exit_at: Optional[datetime] = None
    count: int = 0

    def __str__(self):
        return f"(first_failure: {self.first_failure.isoformat()}, fail count: {self.count})"


SIMPLE_CACHE: dict[str, SimpleCacheItem] = dict()
FAILURE_INFO: dict[str, FailCountItem] = dict()


def log_failure_info(req: ContextRequest, key: str, msg: str, exc: Optional[Exception] = None) -> None:
    if key not in FAILURE_INFO:
        FAILURE_INFO[key] = FailCountItem(first_failure=datetime.utcnow())
    FAILURE_INFO[key].count += 1
    req.app.context.logger.warning(f"{msg} {FAILURE_INFO[key]}: {exc}")


def reset_failure_info(req: ContextRequest, key: str) -> None:
    if key not in FAILURE_INFO:
        return None
    info = FAILURE_INFO.pop(key)
    req.app.context.logger.info(f"Check {key} back to normal. Resetting info {info}")


def check_restart(key, restart: int, terminate: int) -> bool:
    res = False  # default to no restart
    info = FAILURE_INFO.get(key)
    if not info:
        return res
    if restart and not info.restart_at:
        info = replace(info, restart_at=info.first_failure + timedelta(seconds=restart))
    if terminate and not info.exit_at:
        info = replace(info, exit_at=info.first_failure + timedelta(seconds=terminate))
    if info.exit_at and datetime.utcnow() >= info.exit_at:
        # Exit application and rely on something else restarting it
        sys.exit(1)
    if info.restart_at and datetime.utcnow() >= info.restart_at:
        info = replace(info, restart_at=datetime.utcnow() + timedelta(seconds=restart))
        # Try to restart/reinitialize the failing functionality
        res = True
    FAILURE_INFO[key] = info
    return res


def get_cached_response(req: ContextRequest, resp: Response, key: str) -> Optional[Mapping[str, Any]]:
    cache_for_seconds = req.app.context.config.status_cache_seconds
    resp.headers["Cache-Control"] = f"public,max-age={cache_for_seconds}"

    now = datetime.utcnow()
    if SIMPLE_CACHE.get(key) is not None:
        if now < SIMPLE_CACHE[key].expire_time:
            if req.app.context.config.debug:
                req.app.context.logger.debug(
                    f"Returned cached response for {key}" f" {now} < {SIMPLE_CACHE[key].expire_time}"
                )
            resp.headers["Expires"] = SIMPLE_CACHE[key].expire_time.strftime("%a, %d %b %Y %H:%M:%S UTC")
            return SIMPLE_CACHE[key].data
    return None


def set_cached_response(req: ContextRequest, resp: Response, key: str, data: Mapping) -> None:
    cache_for_seconds = req.app.context.config.status_cache_seconds
    now = datetime.utcnow()
    expires = now + timedelta(seconds=cache_for_seconds)
    resp.headers["Expires"] = expires.strftime("%a, %d %b %Y %H:%M:%S UTC")
    SIMPLE_CACHE[key] = SimpleCacheItem(expire_time=expires, data=data)
    if req.app.context.config.debug:
        req.app.context.logger.debug(f"Cached response for {key} until {expires}")


def check_mongo(req: ContextRequest, default_data_owner: str):
    user_db = req.app.context.get_userdb(default_data_owner)
    group_db = req.app.context.get_groupdb(default_data_owner)
    try:
        user_db.is_healthy()
        group_db.is_healthy()
        reset_failure_info(req, "_check_mongo")
        return True
    except Exception as exc:
        log_failure_info(req, "_check_mongo", msg="Mongodb health check failed", exc=exc)
        check_restart("_check_mongo", restart=0, terminate=120)
        return False


def check_neo4j(req: ContextRequest, default_data_owner: str):
    group_db = req.app.context.get_groupdb(default_data_owner)
    try:
        # TODO: Implement is_healthy
        # db.is_healthy()
        q = """
            MATCH (n)
            RETURN count(*) as exists LIMIT 1
            """
        with group_db.graphdb.db.driver.session() as session:
            session.run(q).single()
        reset_failure_info(req, "_check_neo4j")
        return True
    except Exception as exc:
        log_failure_info(req, "_check_neo4j", msg="Neo4j health check failed", exc=exc)
        check_restart("_check_neo4j", restart=0, terminate=120)
        return False
