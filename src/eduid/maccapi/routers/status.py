from collections.abc import Mapping
from os import environ

from fastapi import APIRouter, Response
from pydantic import BaseModel

from eduid.common.fastapi.context_request import ContextRequest
from eduid.common.fastapi.utils import (
    check_restart,
    get_cached_response,
    log_failure_info,
    reset_failure_info,
    set_cached_response,
)

__author__ = "ylle"

status_router = APIRouter(prefix="/status")


class StatusResponse(BaseModel):
    status: str
    hostname: str
    reason: str


def check_mongo(request: ContextRequest) -> bool | None:
    db = request.app.context.db
    try:
        db.is_healthy()
        reset_failure_info(request, "_check_mongo")
        return True
    except Exception as exc:
        log_failure_info(request, "_check_mongo", msg="Mongodb health check failed", exc=exc)
        check_restart("_check_mongo", restart=0, terminate=120)
        return False


@status_router.get("/healthy", response_model=StatusResponse, response_model_exclude_none=True)
async def healthy(request: ContextRequest, response: Response) -> Mapping:
    status = get_cached_response(request, response, key="health_check")
    if not status:
        status = {
            "status": f"STATUS_FAIL_{request.app.context.name}_",
            "hostname": environ.get("HOSTNAME", "UNKNOWN"),
        }
        if not check_mongo(request):
            status["reason"] = "mongodb check failed"
            request.app.context.logger.warning("MongoDB health check failed")
        else:
            status["status"] = f"STATUS_OK_{request.app.context.name}_"
            status["reason"] = "mongodb check succeeded"
        set_cached_response(request, response, key="health_check", data=status)
    return status
