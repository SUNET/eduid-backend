# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
import sys
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from os import environ
from typing import Dict, Mapping, Optional, cast

import redis
from flask import Blueprint, Response, current_app, jsonify

from eduid_common.config.base import BaseConfig, RedisConfig
from eduid_common.session.redis_session import get_redis_pool

status_views = Blueprint('status', __name__, url_prefix='/status')


@dataclass
class SimpleCacheItem:
    expire_time: datetime
    data: Mapping


SIMPLE_CACHE: Dict[str, SimpleCacheItem] = dict()


@dataclass
class FailCountItem:
    first_failure: datetime = field(repr=False)
    restart_at: Optional[datetime] = None
    restart_interval: Optional[int] = None
    exit_at: Optional[datetime] = None
    count: int = 0

    def __str__(self):
        return f'(first_failure: {self.first_failure.isoformat()}, fail count: {self.count})'


FAILURE_INFO: Dict[str, FailCountItem] = dict()


def log_failure_info(key: str, msg: str, exc: Optional[Exception] = None) -> None:
    if key not in FAILURE_INFO:
        FAILURE_INFO[key] = FailCountItem(first_failure=datetime.utcnow())
    FAILURE_INFO[key].count += 1
    current_app.logger.warning(f'{msg} {FAILURE_INFO[key]}: {exc}')


def reset_failure_info(key: str) -> None:
    if key not in FAILURE_INFO:
        return None
    info = FAILURE_INFO.pop(key)
    current_app.logger.info(f'Check {key} back to normal. Resetting info {info}')


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


def _check_mongo():
    db = current_app.central_userdb
    try:
        db.is_healthy()
        reset_failure_info('_check_mongo')
        return True
    except Exception as exc:
        log_failure_info('_check_mongo', msg='Mongodb health check failed', exc=exc)
        check_restart('_check_mongo', restart=0, terminate=120)
        return False


def _check_redis() -> bool:
    pool = get_redis_pool(current_app.config.redis_config)
    client = redis.StrictRedis(connection_pool=pool)
    try:
        pong = client.ping()
        if pong:
            reset_failure_info('_check_redis')
            return True
        log_failure_info('_check_redis', msg=f'Redis health check failed: response == {repr(pong)}')
    except Exception as exc:
        log_failure_info('_check_redis', msg='Redis health check failed', exc=exc)
        check_restart('_check_redis', restart=0, terminate=120)
    return False


def _check_am():
    try:
        res = current_app.am_relay.ping()
        if res == 'pong for {}'.format(current_app.am_relay.relay_for):
            reset_failure_info('_check_am')
            return True
    except Exception as exc:
        log_failure_info('_check_am', msg='am health check failed', exc=exc)
        check_restart('_check_am', restart=0, terminate=120)
    return False


def _check_msg():
    try:
        res = current_app.msg_relay.ping()
        if res == 'pong':
            reset_failure_info('_check_msg')
            return True
    except Exception as exc:
        log_failure_info('_check_msg', msg='msg health check failed', exc=exc)
        check_restart('_check_msg', restart=0, terminate=120)
    return False


def _check_mail():
    try:
        res = current_app.mail_relay.ping()
        if res == 'pong':
            reset_failure_info('_check_mail')
            return True
    except Exception as exc:
        log_failure_info('_check_mail', msg='mail health check failed', exc=exc)
        check_restart('_check_mail', restart=0, terminate=120)
    return False


def cached_json_response(key: str, data: Optional[dict] = None) -> Optional[Response]:
    config = cast(BaseConfig, current_app.config)  # Please mypy
    cache_for_seconds = config.status_cache_seconds
    now = datetime.utcnow()
    if SIMPLE_CACHE.get(key) is not None:
        if now < SIMPLE_CACHE[key].expire_time:
            if current_app.debug:
                current_app.logger.debug(
                    f'Returned cached response for {key}' f' {now} < {SIMPLE_CACHE[key].expire_time}'
                )
            response = jsonify(SIMPLE_CACHE[key].data)
            response.headers.add('Expires', SIMPLE_CACHE[key].expire_time.strftime("%a, %d %b %Y %H:%M:%S UTC"))
            response.headers.add('Cache-Control', f'public,max-age={cache_for_seconds}')
            return response

    # Allow for the function to be called with no data so we can check for a cached response
    # before running the checks
    if data is None:
        return None

    expires = now + timedelta(seconds=cache_for_seconds)
    response = jsonify(data)
    response.headers.add('Expires', expires.strftime("%a, %d %b %Y %H:%M:%S UTC"))
    response.headers.add('Cache-Control', f'public,max-age={cache_for_seconds}')
    SIMPLE_CACHE[key] = SimpleCacheItem(expire_time=expires, data=data)
    if current_app.debug:
        current_app.logger.debug(f'Cached response for {key} until {expires}')
    return response


@status_views.route('/healthy', methods=['GET'])
def health_check():
    response = cached_json_response('health_check')
    if response:
        return response

    res = {
        # Value of status crafted for grepabilty, trailing underscore intentional
        'status': f'STATUS_FAIL_{current_app.name}_',
        'hostname': environ.get('HOSTNAME', 'UNKNOWN'),
    }
    if not _check_mongo():
        res['reason'] = 'mongodb check failed'
        current_app.logger.warning('mongodb check failed')
    elif not _check_redis():
        res['reason'] = 'redis check failed'
        current_app.logger.warning('redis check failed')
    elif getattr(current_app, 'am_relay', False) and not _check_am():
        res['reason'] = 'am check failed'
        current_app.logger.warning('am check failed')
    elif getattr(current_app, 'msg_relay', False) and not _check_msg():
        res['reason'] = 'msg check failed'
        current_app.logger.warning('msg check failed')
    elif getattr(current_app, 'mail_relay', False) and not _check_mail():
        res['reason'] = 'mail check failed'
        current_app.logger.warning('mail check failed')
    else:
        res['status'] = f'STATUS_OK_{current_app.name}_'
        res['reason'] = 'Databases and task queues tested OK'

    return cached_json_response('health_check', res)


@status_views.route('/sanity-check', methods=['GET'])
def sanity_check():
    response = cached_json_response('sanity_check')
    if response:
        return response
    # TODO: Do checks here
    return cached_json_response('sanity_check', {})
