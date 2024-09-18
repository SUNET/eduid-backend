from collections.abc import Mapping
from os import environ

from fastapi import Response

from eduid.common.fastapi.context_request import ContextRequest
from eduid.common.fastapi.utils import get_cached_response, set_cached_response
from eduid.scimapi.api_router import APIRouter
from eduid.scimapi.context_request import ScimApiRoute
from eduid.scimapi.models.status import StatusResponse
from eduid.scimapi.routers.utils.status import check_mongo, check_neo4j

__author__ = "lundberg"


status_router = APIRouter(route_class=ScimApiRoute, prefix="/status")


@status_router.get("/healthy", response_model=StatusResponse, response_model_exclude_none=True)
async def healthy(req: ContextRequest, resp: Response) -> Mapping:
    res = get_cached_response(req=req, resp=resp, key="health_check")
    if not res:
        default_data_owner = list(req.app.context.config.data_owners.keys())[0]
        res = {
            # Value of status crafted for grepabilty, trailing underscore intentional
            "status": f"STATUS_FAIL_{req.app.context.name}_",
            "hostname": environ.get("HOSTNAME", "UNKNOWN"),
        }
        if not check_mongo(req, default_data_owner):
            res["reason"] = "mongodb check failed"
            req.app.context.logger.warning("mongodb check failed")
        elif not check_neo4j(req, default_data_owner):
            res["reason"] = "neo4j check failed"
            req.app.context.logger.warning("neo4j check failed")
        else:
            res["status"] = f"STATUS_OK_{req.app.context.name}_"
            res["reason"] = "Databases tested OK"
        set_cached_response(req=req, resp=resp, key="health_check", data=res)
    return res
