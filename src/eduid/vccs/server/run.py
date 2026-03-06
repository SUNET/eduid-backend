import sys
from asyncio import Lock
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from ndnkdf import ndnkdf
from starlette.responses import JSONResponse
from starlette.status import HTTP_422_UNPROCESSABLE_CONTENT

from eduid.vccs.server.config import init_config
from eduid.vccs.server.db import CredentialDB
from eduid.vccs.server.endpoints.add_creds import add_creds_router
from eduid.vccs.server.endpoints.authenticate import authenticate_router
from eduid.vccs.server.endpoints.misc import misc_router
from eduid.vccs.server.endpoints.revoke_creds import revoke_creds_router
from eduid.vccs.server.hasher import load_hasher
from eduid.vccs.server.log import InterceptHandler, init_logging


class VCCS_API(FastAPI):
    def __init__(self, test_config: Mapping[str, Any] | None = None, lifespan: Callable | None = None) -> None:
        print("vccs_api is starting", file=sys.stderr)
        super().__init__(lifespan=lifespan)

        self.state.config = init_config(ns="api", app_name="vccs", test_config=test_config)

        self.logger = init_logging()

        yhsm_lock = Lock()  # brief testing indicates locking is not needed with asyncio, but...
        self.state.hasher = load_hasher(config=self.state.config.hasher, lock=yhsm_lock, debug=self.state.config.debug)
        self.state.hasher.unlock()

        self.state.new_hasher = None
        if self.state.config.new_hasher is not None:
            new_hasher_lock = Lock()
            self.state.new_hasher = load_hasher(
                config=self.state.config.new_hasher, lock=new_hasher_lock, debug=self.state.config.debug
            )
            self.state.new_hasher.unlock()
            self.logger.info(f"Starting new_hasher: {self.state.new_hasher}")
            self.logger.info(f"new_hasher info: {self.state.new_hasher.info()}")

        self.state.kdf = ndnkdf.NDNKDF()

        self.state.credstore = CredentialDB(db_uri=self.state.config.mongo_uri)

        self.logger.info(f"Starting, hasher {self.state.hasher}")
        self.logger.info(f"hasher info: {self.state.hasher.info()}")


@asynccontextmanager
async def lifespan(app: VCCS_API) -> AsyncIterator[None]:
    """
    Uvicorn mucks with the logging config on startup, particularly the access log. Rein it in.
    """
    import logging

    for k, v in logging.Logger.manager.loggerDict.items():
        app.logger.debug(f"See logger {k}: {v}")
        if k == "uvicorn.error" and isinstance(v, logging.Logger):
            app.logger.debug(f"  {v.level} {v.propagate}")

    for _name in ["uvicorn", "uvicorn.access", "uvicorn.error"]:
        _logger = logging.getLogger(_name)
        _logger.level = logging.DEBUG
        _old_handlers = _logger.handlers
        _logger.handlers = [InterceptHandler()]
        if _name == "uvicorn.access":
            _logger.propagate = False
        app.logger.info(
            f"Updated logger {_name} handlers {_old_handlers} -> {_logger.handlers} (prop: {_logger.propagate})"
        )
    yield
    # shutdown


app = VCCS_API(lifespan=lifespan)
app.include_router(misc_router)  # , prefix='/v1')
app.include_router(add_creds_router)
app.include_router(revoke_creds_router)
app.include_router(authenticate_router)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    request.app.logger.warning(f"Failed parsing request: {exc}")
    return JSONResponse({"errors": exc.errors()}, status_code=HTTP_422_UNPROCESSABLE_CONTENT)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)  # , log_config=None)
