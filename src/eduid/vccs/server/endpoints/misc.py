from enum import StrEnum, unique

from fastapi import APIRouter, Request
from pydantic.main import BaseModel

misc_router = APIRouter()


@unique
class Status(StrEnum):
    # STATUS_x_ is less ambiguous when pattern matching than just 'x'
    OK: str = "STATUS_OK_"
    FAIL: str = "STATUS_FAIL_"


class StatusResponse(BaseModel):
    status: Status
    add_creds_hmac: Status | None = None
    version: int = 1


@misc_router.get("/status/healthy", response_model=StatusResponse)
async def status(request: Request) -> StatusResponse:
    _test_keyhandle = request.app.state.config.add_creds_password_key_handle
    res = StatusResponse(status=Status.OK)
    try:
        hmac = await request.app.state.hasher.hmac_sha1(key_handle=_test_keyhandle, data=b"\0")
        if len(hmac) >= 20:  # length of HMAC-SHA-1
            res.add_creds_hmac = Status.OK
        else:
            res.add_creds_hmac = Status.FAIL
    except Exception:
        request.app.logger.exception(f"Failed hashing test data with key handle {_test_keyhandle}")
        res.add_creds_hmac = Status.FAIL
        res.status = Status.FAIL

    return res


class HMACResponse(BaseModel):
    keyhandle: int
    hmac: str


@misc_router.get("/hmac/{keyhandle}/{data}", response_model=HMACResponse)
async def hmac(request: Request, keyhandle: int, data: bytes) -> HMACResponse:
    hmac = await request.app.state.hasher.hmac_sha1(key_handle=keyhandle, data=data)
    return HMACResponse(keyhandle=keyhandle, hmac=hmac.hex())
