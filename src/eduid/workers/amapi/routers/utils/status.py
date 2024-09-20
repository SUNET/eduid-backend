import sys
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any

from fastapi import Response

from eduid.workers.amapi.context_request import ContextRequest

__author__ = "masv"


@dataclass
class SimpleCacheItem:
    expire_time: datetime
    data: Mapping


@dataclass
class FailCountItem:
    first_failure: datetime = field(repr=False)
    restart_at: datetime | None = None
    restart_interval: int | None = None
    exit_at: datetime | None = None
    count: int = 0

    def __str__(self):
        return f"(first_failure: {self.first_failure.isoformat()}, fail count: {self.count})"


SIMPLE_CACHE: dict[str, SimpleCacheItem] = dict()
FAILURE_INFO: dict[str, FailCountItem] = dict()


def log_failure_info(ctx: ContextRequest, key: str, msg: str, exc: Exception | None = None) -> None:
    if key not in FAILURE_INFO:
        FAILURE_INFO[key] = FailCountItem(first_failure=datetime.utcnow())
    FAILURE_INFO[key].count += 1
    ctx.app.context.logger.warning(f"{msg} {FAILURE_INFO[key]}: {exc}")


def reset_failure_info(ctx: ContextRequest, key: str) -> None:
    if key not in FAILURE_INFO:
        return None
    info = FAILURE_INFO.pop(key)
    ctx.app.context.logger.info(f"Check {key} back to normal. Resetting info {info}")


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


def get_cached_response(ctx: ContextRequest, resp: Response, key: str) -> Mapping[str, Any] | None:
    cache_for_seconds = ctx.app.config.status_cache_seconds
    resp.headers["Cache-Control"] = f"public,max-age={cache_for_seconds}"

    now = datetime.utcnow()
    if SIMPLE_CACHE.get(key) is not None:
        if now < SIMPLE_CACHE[key].expire_time:
            if ctx.app.context.config.debug:
                ctx.app.context.logger.debug(
                    f"Returned cached response for {key} {now} < {SIMPLE_CACHE[key].expire_time}"
                )
            resp.headers["Expires"] = SIMPLE_CACHE[key].expire_time.strftime("%a, %d %b %Y %H:%M:%S UTC")
            return SIMPLE_CACHE[key].data
    return None


def set_cached_response(ctx: ContextRequest, resp: Response, key: str, data: Mapping) -> None:
    cache_for_seconds = ctx.app.config.status_cache_seconds
    now = datetime.utcnow()
    expires = now + timedelta(seconds=cache_for_seconds)
    resp.headers["Expires"] = expires.strftime("%a, %d %b %Y %H:%M:%S UTC")
    SIMPLE_CACHE[key] = SimpleCacheItem(expire_time=expires, data=data)
    if ctx.app.config.debug:
        ctx.app.context.logger.debug(f"Cached response for {key} until {expires}")


def check_mongo(ctx: ContextRequest):
    try:
        ctx.app.context.db.is_healthy()
        reset_failure_info(ctx, "_check_mongo")
        return True
    except Exception as exc:
        log_failure_info(ctx, "_check_mongo", msg="Mongodb health check failed", exc=exc)
        check_restart("_check_mongo", restart=0, terminate=120)
        return False
