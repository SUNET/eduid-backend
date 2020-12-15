from fastapi import APIRouter
from fastapi import Request
from pydantic.main import BaseModel

misc_router = APIRouter()


@misc_router.get("/status")
async def status(request: Request):
    status = request.app.state.hasher._yhsm.info()
    return {'yhsm': str(status)}


class HMACResponse(BaseModel):
    keyhandle: int
    hmac: str


@misc_router.get("/hmac/{keyhandle}/{data}", response_model=HMACResponse)
async def hmac(request: Request, keyhandle: int, data: bytes):
    hmac = await request.app.state.hasher.hmac_sha1(key_handle=keyhandle, data=data)
    return HMACResponse(keyhandle=str(keyhandle), hmac=hmac.hex())

