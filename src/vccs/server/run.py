from asyncio import Lock
from binascii import unhexlify

from fastapi import FastAPI
from pydantic.main import BaseModel

from vccs.server.hasher import hasher_from_string
from vccs.server.log import InterceptHandler, init_logging


class VCCS_API(FastAPI):
    def __init__(self):
        super().__init__()

        yhsm_lock = Lock()  # brief testing indicates locking is not needed with asyncio, but...
        self.hasher = hasher_from_string(name='/dev/ttyACM0', lock=yhsm_lock, debug=False)
        self.hasher._yhsm.unlock(unhexlify('badabada'))

        self.logger = init_logging()

        self.logger.info(f'Starting, YHSM {self.hasher}')
        self.logger.info(f'YHSM status: {self.hasher._yhsm.info()}')

app = VCCS_API()


@app.on_event("startup")
async def startup_event():
    import logging
    for _name in ['uvicorn', 'uvicorn.access', 'uvicorn.error']:
        _logger = logging.getLogger(_name)
        _logger.level = logging.DEBUG
        _old_handlers = _logger.handlers
        _logger.handlers = [InterceptHandler()]
        _logger.propagate = False
        app.logger.info(f'Updated logger {_name} handlers {_old_handlers} -> {_logger.handlers} (prop: {_logger.propagate})')



@app.get("/status")
async def status():
    status = app.hasher._yhsm.info()
    return {'yhsm': str(status)}


class HMACResponse(BaseModel):
    keyhandle: int
    hmac: str


@app.get("/hmac/{keyhandle}/{data}", response_model=HMACResponse)
async def hmac(keyhandle: int, data: bytes):
    hmac = await app.hasher.hmac_sha1(key_handle=keyhandle, data=data)
    return HMACResponse(keyhandle=str(keyhandle), hmac=hmac.hex())


if __name__ == "__main__":
    import uvicorn

    log_config = None
    uvicorn.run(app, host="0.0.0.0", port=8000, log_config=log_config)
