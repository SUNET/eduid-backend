from eduid.common.fastapi.context_request import ContextRequest
from eduid.common.fastapi.routers.status import create_status_router
from eduid.common.fastapi.utils import check_restart, log_failure_info, reset_failure_info

__author__ = "ylle"


def check_mongo(request: ContextRequest) -> bool:
    db = request.app.context.db
    try:
        db.is_healthy()
        reset_failure_info(request, "_check_mongo")
        return True
    except Exception as exc:
        log_failure_info(request, "_check_mongo", msg="Mongodb health check failed", exc=exc)
        check_restart("_check_mongo", restart=0, terminate=120)
        return False


status_router = create_status_router(checks=[check_mongo])
