# -*- coding: utf-8 -*-
import sys
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from os import environ
from typing import Dict, Mapping, Optional

from falcon import Request, Response

from eduid_scimapi.context import Context
from eduid_scimapi.resources.base import BaseResource

__author__ = 'lundberg'


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
        return f'(first_failure: {self.first_failure.isoformat()}, fail count: {self.count})'


class StatusResource(BaseResource):
    def __init__(self, context: Context):
        super().__init__(context=context)
        self.SIMPLE_CACHE: Dict[str, SimpleCacheItem] = dict()
        self.FAILURE_INFO: Dict[str, FailCountItem] = dict()

    def log_failure_info(self, key: str, msg: str, exc: Optional[Exception] = None) -> None:
        if key not in self.FAILURE_INFO:
            self.FAILURE_INFO[key] = FailCountItem(first_failure=datetime.utcnow())
        self.FAILURE_INFO[key].count += 1
        self.context.logger.warning(f'{msg} {self.FAILURE_INFO[key]}: {exc}')

    def reset_failure_info(self, key: str) -> None:
        if key not in self.FAILURE_INFO:
            return None
        info = self.FAILURE_INFO.pop(key)
        self.context.logger.info(f'Check {key} back to normal. Resetting info {info}')

    def check_restart(self, key, restart: int, terminate: int) -> bool:
        res = False  # default to no restart
        info = self.FAILURE_INFO.get(key)
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
        self.FAILURE_INFO[key] = info
        return res

    def get_cached_response(self, resp: Response, key: str) -> bool:
        cache_for_seconds = self.context.config.status_cache_seconds
        resp.set_header('Cache-Control', f'public,max-age={cache_for_seconds}')

        now = datetime.utcnow()
        if self.SIMPLE_CACHE.get(key) is not None:
            if now < self.SIMPLE_CACHE[key].expire_time:
                if self.context.config.debug:
                    self.context.logger.debug(
                        f'Returned cached response for {key}' f' {now} < {self.SIMPLE_CACHE[key].expire_time}'
                    )
                resp.media = self.SIMPLE_CACHE[key].data
                resp.set_header('Expires', self.SIMPLE_CACHE[key].expire_time.strftime("%a, %d %b %Y %H:%M:%S UTC"))
                return True
        return False

    def set_cached_response(self, resp: Response, key: str, data: Mapping) -> None:
        cache_for_seconds = self.context.config.status_cache_seconds
        now = datetime.utcnow()
        expires = now + timedelta(seconds=cache_for_seconds)
        resp.media = data
        resp.set_header('Expires', expires.strftime("%a, %d %b %Y %H:%M:%S UTC"))
        self.SIMPLE_CACHE[key] = SimpleCacheItem(expire_time=expires, data=data)
        if self.context.config.debug:
            self.context.logger.debug(f'Cached response for {key} until {expires}')


class HealthCheckResource(StatusResource):
    def _check_mongo(self):
        user_db = self.context.get_userdb(self.context.config.data_owners[0])
        group_db = self.context.get_groupdb(self.context.config.data_owners[0])
        try:
            user_db.is_healthy()
            group_db.is_healthy()
            self.reset_failure_info('_check_mongo')
            return True
        except Exception as exc:
            self.log_failure_info('_check_mongo', msg='Mongodb health check failed', exc=exc)
            self.check_restart('_check_mongo', restart=0, terminate=120)
            return False

    def _check_neo4j(self):
        group_db = self.context.get_groupdb(self.context.config.data_owners[0])
        try:
            # TODO: Implement is_healthy
            # db.is_healthy()
            q = """
                MATCH (n)             
                RETURN count(*) as exists LIMIT 1
                """
            with group_db.graphdb.db.driver.session() as session:
                session.run(q).single()
            self.reset_failure_info('_check_neo4j')
            return True
        except Exception as exc:
            self.log_failure_info('_check_neo4j', msg='Neo4j health check failed', exc=exc)
            self.check_restart('_check_neo4j', restart=0, terminate=120)
            return False

    def on_get(self, req: Request, resp: Response):
        if not self.get_cached_response(resp=resp, key='health_check'):
            res = {
                # Value of status crafted for grepabilty, trailing underscore intentional
                'status': f'STATUS_FAIL_{self.context.name}_',
                'hostname': environ.get('HOSTNAME', 'UNKNOWN'),
            }
            if not self._check_mongo():
                res['reason'] = 'mongodb check failed'
                self.context.logger.warning('mongodb check failed')
            elif not self._check_neo4j():
                res['reason'] = 'neo4j check failed'
                self.context.logger.warning('neo4j check failed')
            else:
                res['status'] = f'STATUS_OK_{self.context.name}_'
                res['reason'] = 'Databases tested OK'
            self.set_cached_response(resp=resp, key='health_check', data=res)
