from enum import StrEnum, unique

from fastapi import APIRouter, Request
from pydantic.main import BaseModel

misc_router = APIRouter()

HMAC_SHA1_LENGTH = 20
HMAC_SHA256_LENGTH = 32


@unique
class Status(StrEnum):
    # STATUS_x_ is less ambiguous when pattern matching than just 'x'
    OK = "STATUS_OK_"
    FAIL = "STATUS_FAIL_"


class StatusResponse(BaseModel):
    status: Status
    add_creds_hmac: Status | None = None
    new_hasher_hmac: Status | None = None
    version: int = 1


@misc_router.get("/status/healthy")
async def status(request: Request) -> StatusResponse:
    _test_keyhandle = request.app.state.config.hasher.add_creds_password_key_handle
    res = StatusResponse(status=Status.OK)
    try:
        hmac = await request.app.state.hasher.hmac_sha1(key_handle=_test_keyhandle, data=b"\0")
        if len(hmac) >= HMAC_SHA1_LENGTH:  # length of HMAC-SHA-1
            res.add_creds_hmac = Status.OK
        else:
            res.add_creds_hmac = Status.FAIL
    except Exception:
        request.app.logger.exception(f"Failed hashing test data with key handle {_test_keyhandle}")
        res.add_creds_hmac = Status.FAIL
        res.status = Status.FAIL

    # Check new_hasher if configured
    if request.app.state.new_hasher is not None:
        _new_hasher_config = request.app.state.config.new_hasher
        _test_key_label = _new_hasher_config.add_creds_password_key_label if _new_hasher_config else None
        if _test_key_label is not None:
            try:
                hmac256 = await request.app.state.new_hasher.hmac_sha256(key_label=_test_key_label, data=b"\0")
                if len(hmac256) >= HMAC_SHA256_LENGTH:
                    res.new_hasher_hmac = Status.OK
                else:
                    res.new_hasher_hmac = Status.FAIL
            except Exception:
                request.app.logger.exception(f"Failed hashing test data with new_hasher key label {_test_key_label}")
                res.new_hasher_hmac = Status.FAIL
                res.status = Status.FAIL
        else:
            request.app.logger.warning("new_hasher configured but no add_creds_password_key_label set")
            res.new_hasher_hmac = Status.FAIL
            res.status = Status.FAIL

    return res


class HMACResponse(BaseModel):
    keyhandle: int
    hmac: str


@misc_router.get("/hmac/{keyhandle}/{data}")
async def hmac(request: Request, keyhandle: int, data: bytes) -> HMACResponse:
    hmac = await request.app.state.hasher.hmac_sha1(key_handle=keyhandle, data=data)
    return HMACResponse(keyhandle=keyhandle, hmac=hmac.hex())
