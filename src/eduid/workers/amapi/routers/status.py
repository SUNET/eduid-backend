# -*- coding: utf-8 -*-
from os import environ
from typing import Mapping

from fastapi import Response

from eduid.workers.amapi.api_router import APIRouter
from eduid.workers.amapi.context_request import ContextRequest, ContextRequestRoute
from eduid.workers.amapi.models.status import StatusResponse
from eduid.workers.amapi.routers.utils.status import check_mongo, get_cached_response, set_cached_response

__author__ = 'masv'


status_router = APIRouter(route_class=ContextRequestRoute, prefix='/status')


@status_router.get('/healthy', response_model=StatusResponse, response_model_exclude_none=True)
async def healthy(ctx: ContextRequest, resp: Response) -> Mapping:
    res = get_cached_response(ctx=ctx, resp=resp, key='health_check')
    if not res:
        res = {
            # Value of status crafted for grepabilty, trailing underscore intentional
            'status': f'STATUS_FAIL_{ctx.app.name}_',
            'hostname': environ.get('HOSTNAME', 'UNKNOWN'),
        }
        if not check_mongo(ctx):
            res['reason'] = 'mongodb check failed'
            ctx.app.logger.warning('mongodb check failed')
        else:
            res['status'] = f'STATUS_OK_{ctx.app.name}_'
            res['reason'] = 'Databases tested OK'
        set_cached_response(ctx=ctx, resp=resp, key='health_check', data=res)
    return res
