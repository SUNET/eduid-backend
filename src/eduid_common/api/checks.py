# -*- coding: utf-8 -*-
import sys
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from os import environ
from typing import Optional

import redis
from flask import current_app

from eduid_common.authn.vccs import check_password
from eduid_common.config.base import VCCSConfigMixin
from eduid_common.session.redis_session import get_redis_pool

__author__ = 'lundberg'


@dataclass
class CheckResult:
    healthy: bool
    status: Optional[str] = None
    hostname: str = field(default_factory=lambda: environ.get('HOSTNAME', 'UNKNOWN'))
    reason: Optional[str] = None


@dataclass
class FailCountItem:
    first_failure: datetime = field(repr=False)
    restart_at: Optional[datetime] = None
    restart_interval: Optional[int] = None
    exit_at: Optional[datetime] = None
    count: int = 0

    def __str__(self):
        return f'(first_failure: {self.first_failure.isoformat()}, fail count: {self.count})'


def log_failure_info(key: str, msg: str, exc: Optional[Exception] = None) -> None:
    if key not in current_app.failure_info:
        current_app.failure_info[key] = FailCountItem(first_failure=datetime.utcnow())
    current_app.failure_info[key].count += 1
    current_app.logger.warning(f'{msg} {current_app.failure_info[key]}: {exc}')


def reset_failure_info(key: str) -> None:
    if key not in current_app.failure_info:
        return None
    info = current_app.failure_info.pop(key)
    current_app.logger.info(f'Check {key} back to normal. Resetting info {info}')


def check_restart(key, restart: int, terminate: int) -> bool:
    res = False  # default to no restart
    info = current_app.failure_info.get(key)
    if not info:
        return res
    if restart and not info.restart_at:
        info = replace(info, restart_at=info.first_failure + timedelta(seconds=restart))
    if terminate and not info.exit_at:
        info = replace(info, exit_at=info.first_failure + timedelta(seconds=terminate))
    if info.exit_at and datetime.utcnow() >= info.exit_at:
        # Exit application and rely on something else restarting it
        current_app.logger.warning(f'Max failure time reached, terminating {current_app.name}')
        sys.exit(1)
    if info.restart_at and datetime.utcnow() >= info.restart_at:
        info = replace(info, restart_at=datetime.utcnow() + timedelta(seconds=restart))
        # Try to restart/reinitialize the failing functionality
        res = True
    current_app.failure_info[key] = info
    return res


def check_mongo() -> bool:
    db = current_app.central_userdb
    try:
        db.is_healthy()
        reset_failure_info('check_mongo')
        return True
    except Exception as exc:
        log_failure_info('check_mongo', msg='Mongodb health check failed', exc=exc)
        check_restart('check_mongo', restart=0, terminate=120)
        return False


def check_redis() -> bool:
    pool = get_redis_pool(current_app.conf.redis_config)
    client = redis.StrictRedis(connection_pool=pool)
    try:
        pong = client.ping()
        if pong:
            reset_failure_info('check_redis')
            return True
        log_failure_info('check_redis', msg=f'Redis health check failed: response == {repr(pong)}')
    except Exception as exc:
        log_failure_info('check_redis', msg='Redis health check failed', exc=exc)
        check_restart('check_redis', restart=0, terminate=120)
    return False


def check_am() -> bool:
    if not getattr(current_app, 'am_relay', False):
        return True
    try:
        res = current_app.am_relay.ping()
        if res == 'pong for {}'.format(current_app.am_relay.relay_for):
            reset_failure_info('check_am')
            return True
    except Exception as exc:
        log_failure_info('check_am', msg='am health check failed', exc=exc)
        check_restart('check_am', restart=0, terminate=120)
    return False


def check_msg() -> bool:
    if not getattr(current_app, 'msg_relay', False):
        return True
    try:
        res = current_app.msg_relay.ping()
        if res == 'pong':
            reset_failure_info('check_msg')
            return True
    except Exception as exc:
        log_failure_info('check_msg', msg='msg health check failed', exc=exc)
        check_restart('check_msg', restart=0, terminate=120)
    return False


def check_mail() -> bool:
    if not getattr(current_app, 'mail_relay', False):
        return True
    try:
        res = current_app.mail_relay.ping()
        if res == 'pong':
            reset_failure_info('check_mail')
            return True
    except Exception as exc:
        log_failure_info('check_mail', msg='mail health check failed', exc=exc)
        check_restart('check_mail', restart=0, terminate=120)
    return False


def check_vccs() -> bool:
    if not isinstance(current_app.conf, VCCSConfigMixin):
        return True
    # Do not force this check if not configured
    if not current_app.conf.vccs_check_eppn:
        return True
    try:
        user = current_app.central_userdb.get_user_by_eppn(
            eppn=current_app.conf.vccs_check_eppn, raise_on_missing=False
        )
        vccs_url = current_app.conf.vccs_url
        password = current_app.conf.vccs_check_password
        if user and check_password(password=password, user=user, vccs_url=vccs_url):
            return True
    except Exception as exc:
        log_failure_info('check_vccs', msg='vccs health check failed', exc=exc)
        check_restart('check_vccs', restart=0, terminate=120)
    return False
