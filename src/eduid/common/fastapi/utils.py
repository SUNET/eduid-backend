__author__ = "lundberg"


import sys
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any

from fastapi import Response

from eduid.common.fastapi.context_request import ContextRequest
from eduid.common.misc.timeutil import utc_now


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

    def __str__(self) -> str:
        return f"(first_failure: {self.first_failure.isoformat()}, fail count: {self.count})"


SIMPLE_CACHE: dict[str, SimpleCacheItem] = dict()
FAILURE_INFO: dict[str, FailCountItem] = dict()


def log_failure_info(req: ContextRequest, key: str, msg: str, exc: Exception | None = None) -> None:
    if key not in FAILURE_INFO:
        FAILURE_INFO[key] = FailCountItem(first_failure=utc_now())
    FAILURE_INFO[key].count += 1
    req.app.context.logger.warning(f"{msg} {FAILURE_INFO[key]}: {exc}")


def reset_failure_info(req: ContextRequest, key: str) -> None:
    if key not in FAILURE_INFO:
        return None
    info = FAILURE_INFO.pop(key)
    req.app.context.logger.info(f"Check {key} back to normal. Resetting info {info}")


def check_restart(key: str, restart: int, terminate: int) -> bool:
    res = False  # default to no restart
    info = FAILURE_INFO.get(key)
    if not info:
        return res
    if restart and not info.restart_at:
        info = replace(info, restart_at=info.first_failure + timedelta(seconds=restart))
    if terminate and not info.exit_at:
        info = replace(info, exit_at=info.first_failure + timedelta(seconds=terminate))
    if info.exit_at and utc_now() >= info.exit_at:
        # Exit application and rely on something else restarting it
        sys.exit(1)
    if info.restart_at and utc_now() >= info.restart_at:
        info = replace(info, restart_at=utc_now() + timedelta(seconds=restart))
        # Try to restart/reinitialize the failing functionality
        res = True
    FAILURE_INFO[key] = info
    return res


def get_cached_response(req: ContextRequest, resp: Response, key: str) -> Mapping[str, Any] | None:
    cache_for_seconds = req.app.context.config.status_cache_seconds
    resp.headers["Cache-Control"] = f"public,max-age={cache_for_seconds}"

    now = utc_now()
    if SIMPLE_CACHE.get(key) is not None and now < SIMPLE_CACHE[key].expire_time:
        if req.app.context.config.debug:
            req.app.context.logger.debug(f"Returned cached response for {key} {now} < {SIMPLE_CACHE[key].expire_time}")
        resp.headers["Expires"] = SIMPLE_CACHE[key].expire_time.strftime("%a, %d %b %Y %H:%M:%S UTC")
        return SIMPLE_CACHE[key].data
    return None


def set_cached_response(req: ContextRequest, resp: Response, key: str, data: Mapping) -> None:
    cache_for_seconds = req.app.context.config.status_cache_seconds
    now = utc_now()
    expires = now + timedelta(seconds=cache_for_seconds)
    resp.headers["Expires"] = expires.strftime("%a, %d %b %Y %H:%M:%S UTC")
    SIMPLE_CACHE[key] = SimpleCacheItem(expire_time=expires, data=data)
    if req.app.context.config.debug:
        req.app.context.logger.debug(f"Cached response for {key} until {expires}")
