from enum import Enum, unique
from fastapi import APIRouter, Request
from pydantic import BaseModel

__author__ = "ylle"

status_router = APIRouter(prefix="/status")

@unique
class Status(str, Enum):
    # STATUS_x_ is less ambiguous when pattern matching than just 'x'
    OK: str = "STATUS_OK_"
    FAIL: str = "STATUS_FAIL_"


class StatusResponse(BaseModel):
    status: Status
    version: int = 1

@status_router.get("/healthy", response_model=StatusResponse)
async def healthy(request: Request) -> StatusResponse:
    response = StatusResponse(status=Status.OK)
    return response
    