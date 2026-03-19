from eduid.common.fastapi.context_request import ContextRequest, ContextRequestRoute
from eduid.common.fastapi.routers.status import create_status_router
from eduid.common.fastapi.utils import check_restart, log_failure_info, reset_failure_info
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.workers.job_runner.scheduler import JobScheduler


def check_mongo(request: ContextRequest) -> bool:
    try:
        db = request.app.context.central_db
    except RuntimeError:
        # app does not have a central_userdb
        return True
    try:
        db.is_healthy()
        reset_failure_info(request, key="_check_mongo")
        return True
    except Exception as exc:
        log_failure_info(request, key="_check_mongo", msg="Mongodb health check failed", exc=exc)
        check_restart("_check_mongo", restart=0, terminate=120)
        return False


def check_am(request: ContextRequest) -> bool:
    am_relay: AmRelay | None = getattr(request.app.context, "am_relay", None)
    if not am_relay:
        return True
    try:
        res = am_relay.ping()
        if res == f"pong for {am_relay.app_name}":
            reset_failure_info(request, key="_check_am")
            return True
    except Exception as exc:
        log_failure_info(request, key="_check_am", msg="am health check failed", exc=exc)
        check_restart(key="_check_am", restart=0, terminate=120)
    return False


def check_msg(request: ContextRequest) -> bool:
    msg_relay: MsgRelay | None = getattr(request.app.context, "msg_relay", None)
    if not msg_relay:
        return True
    try:
        res = msg_relay.ping()
        if res == f"pong for {msg_relay.app_name}":
            reset_failure_info(request, key="_check_msg")
            return True
    except Exception as exc:
        log_failure_info(request, key="_check_msg", msg="msg health check failed", exc=exc)
        check_restart("_check_msg", restart=0, terminate=120)
    return False


def check_scheduler(request: ContextRequest) -> bool:
    scheduler: JobScheduler = request.app.scheduler
    return scheduler.running


status_router = create_status_router(
    checks=[check_mongo, check_am, check_msg, check_scheduler],
    route_class=ContextRequestRoute,
)
