from __future__ import annotations

import sys
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from os import environ
from typing import TYPE_CHECKING, cast

import redis
from flask import current_app as flask_current_app

from eduid.common.config.base import EduIDBaseAppConfig, RedisConfigMixin, VCCSConfigMixin
from eduid.common.misc.timeutil import utc_now
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.rpc.lookup_mobile_relay import LookupMobileRelay
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.webapp.common.authn.vccs import check_password
from eduid.webapp.common.session.redis_session import get_redis_pool

if TYPE_CHECKING:
    from eduid.webapp.common.api.app import EduIDBaseApp

__author__ = "lundberg"


def get_current_app() -> EduIDBaseApp:
    from eduid.webapp.common.api.app import EduIDBaseApp

    _conf = getattr(flask_current_app, "conf")
    assert isinstance(_conf, EduIDBaseAppConfig)
    return cast(EduIDBaseApp, flask_current_app)


@dataclass
class CheckResult:
    healthy: bool
    status: str | None = None
    hostname: str = field(default_factory=lambda: environ.get("HOSTNAME", "UNKNOWN"))
    reason: str | None = None


@dataclass
class FailCountItem:
    first_failure: datetime = field(repr=False)
    restart_at: datetime | None = None
    restart_interval: int | None = None
    exit_at: datetime | None = None
    count: int = 0

    def __str__(self) -> str:
        return f"(first_failure: {self.first_failure.isoformat()}, fail count: {self.count})"


def log_failure_info(key: str, msg: str, exc: Exception | None = None) -> None:
    current_app = get_current_app()

    if key not in current_app.failure_info:
        current_app.failure_info[key] = FailCountItem(first_failure=utc_now())
    current_app.failure_info[key].count += 1
    current_app.logger.warning(f"{msg} {current_app.failure_info[key]}: {exc}")


def reset_failure_info(key: str) -> None:
    current_app = get_current_app()

    if key not in current_app.failure_info:
        return None
    info = current_app.failure_info.pop(key)
    current_app.logger.info(f"Check {key} back to normal. Resetting info {info}")


def check_restart(key: str, restart: int, terminate: int) -> bool:
    current_app = get_current_app()

    res = False  # default to no restart
    info = current_app.failure_info.get(key)
    if not info:
        return res
    if restart and not info.restart_at:
        info = replace(info, restart_at=info.first_failure + timedelta(seconds=restart))
    if terminate and not info.exit_at:
        info = replace(info, exit_at=info.first_failure + timedelta(seconds=terminate))
    if info.exit_at and utc_now() >= info.exit_at:
        # Exit application and rely on something else restarting it
        current_app.logger.warning(f"Max failure time reached, terminating {current_app.name}")
        sys.exit(1)
    if info.restart_at and utc_now() >= info.restart_at:
        info = replace(info, restart_at=utc_now() + timedelta(seconds=restart))
        # Try to restart/reinitialize the failing functionality
        res = True
    current_app.failure_info[key] = info
    return res


def check_mongo() -> bool:
    current_app = get_current_app()

    try:
        db = current_app.central_userdb
    except RuntimeError:
        # app does not have a central_userdb
        return True

    try:
        db.is_healthy()
        reset_failure_info("check_mongo")
        return True
    except Exception as exc:
        log_failure_info("check_mongo", msg="Mongodb health check failed", exc=exc)
        check_restart("check_mongo", restart=0, terminate=120)
        return False


def check_redis() -> bool:
    current_app = get_current_app()
    _conf = getattr(current_app, "conf")
    assert isinstance(_conf, RedisConfigMixin)
    pool = get_redis_pool(_conf.redis_config)
    client = redis.StrictRedis(connection_pool=pool)
    try:
        pong = client.ping()
        if pong:
            reset_failure_info("check_redis")
            return True
        log_failure_info("check_redis", msg=f"Redis health check failed: response == {repr(pong)}")
    except Exception as exc:
        log_failure_info("check_redis", msg="Redis health check failed", exc=exc)
        check_restart("check_redis", restart=0, terminate=120)
    return False


def check_am() -> bool:
    current_app = get_current_app()

    am_relay: AmRelay | None = getattr(current_app, "am_relay", None)
    if not am_relay:
        return True
    try:
        res = am_relay.ping()
        if res == f"pong for {am_relay.app_name}":
            reset_failure_info("check_am")
            return True
    except Exception as exc:
        log_failure_info("check_am", msg="am health check failed", exc=exc)
        check_restart("check_am", restart=0, terminate=120)
    return False


def check_msg() -> bool:
    current_app = get_current_app()

    msg_relay: MsgRelay | None = getattr(current_app, "msg_relay", None)
    if not msg_relay:
        return True
    try:
        res = msg_relay.ping()
        # TODO: remove the backwards-compat startswith when all clients and workers are deployed
        if res == f"pong for {msg_relay.app_name}" or res.startswith("pong"):
            reset_failure_info("check_msg")
            return True
    except Exception as exc:
        log_failure_info("check_msg", msg="msg health check failed", exc=exc)
        check_restart("check_msg", restart=0, terminate=120)
    return False


def check_lookup_mobile() -> bool:
    current_app = get_current_app()

    _relay: LookupMobileRelay | None = getattr(current_app, "lookup_mobile_relay", None)
    if not _relay:
        return True
    try:
        res = _relay.ping()
        if res == f"pong for {_relay.app_name}":
            reset_failure_info("check_lookup_mobile")
            return True
    except Exception as exc:
        log_failure_info("check_lookup_mobile", msg="lookup_mobile health check failed", exc=exc)
        check_restart("check_lookup_mobile", restart=0, terminate=120)
    return False


def check_vccs() -> bool:
    current_app = get_current_app()

    _conf = getattr(current_app, "conf")
    if not isinstance(_conf, VCCSConfigMixin):
        return True
    # Do not force this check if not configured
    if not _conf.vccs_check_eppn:
        return True
    try:
        user = current_app.central_userdb.get_user_by_eppn(eppn=_conf.vccs_check_eppn)
        vccs_url = _conf.vccs_url
        password = _conf.vccs_check_password
        if user and check_password(password=password, user=user, vccs_url=vccs_url):
            return True
    except Exception as exc:
        log_failure_info("check_vccs", msg="vccs health check failed", exc=exc)
        check_restart("check_vccs", restart=0, terminate=120)
    return False
