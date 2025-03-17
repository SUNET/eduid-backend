from collections.abc import Mapping
from os import environ

from fastapi import APIRouter, Response
from pydantic import BaseModel

from eduid.common.fastapi.context_request import ContextRequest, ContextRequestRoute
from eduid.common.fastapi.utils import (
    check_restart,
    get_cached_response,
    log_failure_info,
    reset_failure_info,
    set_cached_response,
)
from eduid.workers.job_runner.scheduler import JobScheduler

status_router = APIRouter(route_class=ContextRequestRoute, prefix="/status")


class StatusResponse(BaseModel):
    status: str
    hostname: str
    reason: str


def check_mongo(request: ContextRequest) -> bool | None:
    try:
        db = request.app.context.central_db
    except RuntimeError:
        # app does not have a central_userdb
        return True
    try:
        db.is_healthy()
        reset_failure_info(request, "_check_mongo")
        return True
    except Exception as exc:
        log_failure_info(request, "_check_mongo", msg="Mongodb health check failed", exc=exc)
        check_restart("_check_mongo", restart=0, terminate=120)
        return False


def check_scheduler(request: ContextRequest) -> bool:
    scheduler: JobScheduler = request.app.scheduler
    return scheduler.running


@status_router.get("/healthy", response_model=StatusResponse)
async def healthy(request: ContextRequest, response: Response) -> Mapping:
    status = get_cached_response(request, response, key="health_check")
    if not status:
        status = {
            "status": f"STATUS_FAIL_{request.app.context.name}_",
            "hostname": environ.get("HOSTNAME", "UNKNOWN"),
        }
        reasons = []
        if not check_mongo(request):
            reasons.append("mongodb check failed")
            request.app.context.logger.warning("MongoDB health check failed")
        elif not check_scheduler(request):
            reasons.append("scheduler check failed")
            request.app.context.logger.warning("APScheduler health check failed")
        else:
            status["status"] = f"STATUS_OK_{request.app.context.name}_"
            reasons.append("mongodb check succeeded")
        status["reason"] = ", ".join(reasons)
        set_cached_response(request, response, key="health_check", data=status)
    return status
