from asyncio import Lock
from typing import Any, Mapping, Optional

from binascii import unhexlify

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from ndnkdf import ndnkdf
from starlette.responses import JSONResponse
from starlette.status import HTTP_422_UNPROCESSABLE_ENTITY

from vccs.server.config import init_config
from vccs.server.db import CredentialDB
from vccs.server.endpoints.add_creds import add_creds_router
from vccs.server.endpoints.authenticate import authenticate_router
from vccs.server.endpoints.misc import misc_router
from vccs.server.endpoints.revoke_creds import revoke_creds_router
from vccs.server.hasher import hasher_from_string
from vccs.server.log import InterceptHandler, init_logging


class VCCS_API(FastAPI):
    def __init__(self, test_config: Optional[Mapping[str, Any]] = None):
        super().__init__()

        self.state.config = init_config(ns='eduid/api', app_name='vccs', test_config=test_config)

        self.logger = init_logging()

        yhsm_lock = Lock()  # brief testing indicates locking is not needed with asyncio, but...
        self.state.hasher = hasher_from_string(
            name=self.state.config.yhsm_device, lock=yhsm_lock, debug=self.state.config.yhsm_debug
        )
        if self.state.config.yhsm_unlock_password:
            self.state.hasher.unlock(unhexlify(self.state.config.yhsm_unlock_password))

        self.state.kdf = ndnkdf.NDNKDF()

        self.state.credstore = CredentialDB(db_uri=self.state.config.mongo_uri)

        self.logger.info(f'Starting, hasher {self.state.hasher}')
        self.logger.info(f'hasher info: {self.state.hasher.info()}')


app = VCCS_API()
app.include_router(misc_router)  # , prefix='/v1')
app.include_router(add_creds_router)
app.include_router(revoke_creds_router)
app.include_router(authenticate_router)


@app.on_event("startup")
async def startup_event():
    """
    Uvicorn mucks with the logging config on startup, particularly the access log. Rein it in.
    """
    import logging

    for k, v in logging.Logger.manager.loggerDict.items():
        app.logger.debug(f'See logger {k}: {v}')
        if k == 'uvicorn.error':
            app.logger.debug(f'  {v.level} {v.propagate}')

    for _name in ['uvicorn', 'uvicorn.access', 'uvicorn.error']:
        _logger = logging.getLogger(_name)
        _logger.level = logging.DEBUG
        _old_handlers = _logger.handlers
        _logger.handlers = [InterceptHandler()]
        if _name == 'uvicorn.access':
            _logger.propagate = False
        app.logger.info(
            f'Updated logger {_name} handlers {_old_handlers} -> {_logger.handlers} ' f'(prop: {_logger.propagate})'
        )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    request.app.logger.warning(f'Failed parsing request: {exc}')
    return JSONResponse({"errors": exc.errors()}, status_code=HTTP_422_UNPROCESSABLE_ENTITY)


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(app, host='0.0.0.0', port=8000)  # , log_config=None)
