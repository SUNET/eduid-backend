from collections.abc import Callable, Mapping
from os import environ
from typing import Any

from fastapi import Response
from fastapi.routing import APIRoute
from pydantic import BaseModel

from eduid.common.fastapi.api_router import APIRouter
from eduid.common.fastapi.context_request import ContextRequest
from eduid.common.fastapi.utils import get_cached_response, set_cached_response


class StatusResponse(BaseModel):
    status: str
    hostname: str
    reason: str | None = None


def create_status_router(
    checks: list[Callable[[ContextRequest], bool]],
    route_class: type[APIRoute] | None = None,
) -> APIRouter:
    kwargs: dict[str, Any] = {"prefix": "/status"}
    if route_class is not None:
        kwargs["route_class"] = route_class
    router = APIRouter(**kwargs)

    @router.get("/ping")
    async def ping() -> Response:
        return Response(status_code=200)

    @router.get("/healthy", response_model=StatusResponse, response_model_exclude_none=True)
    async def healthy(request: ContextRequest, response: Response) -> Mapping[str, Any]:
        cache_key = f"health_check_{request.app.context.name}"
        res = get_cached_response(request, response, key=cache_key)
        if not res:
            res = {
                # Value of status crafted for grepability, trailing underscore intentional
                "status": f"STATUS_FAIL_{request.app.context.name}_",
                "hostname": environ.get("HOSTNAME", "UNKNOWN"),
            }
            failures = [check.__name__ for check in checks if not check(request)]
            if failures:
                res["reason"] = ", ".join(f"{name} failed" for name in failures)
            else:
                res["status"] = f"STATUS_OK_{request.app.context.name}_"
                res["reason"] = "all checks OK"
            set_cached_response(request, response, key=cache_key, data=res)
        return res

    return router
