from fastapi import FastAPI

from eduid.common.config.parsers import load_config
from eduid.common.fastapi.exceptions import (
    HTTPErrorDetail,
    RequestValidationError,
    http_error_detail_handler,
    unexpected_error_handler,
    validation_exception_handler,
)
from eduid.workers.amapi.config import AMApiConfig
from eduid.workers.amapi.context import Context
from eduid.workers.amapi.context_request import ContextRequestRoute
from eduid.workers.amapi.middleware import AuthenticationMiddleware
from eduid.workers.amapi.routers.status import status_router
from eduid.workers.amapi.routers.users import users_router


class AMAPI(FastAPI):
    def __init__(self, name: str = "am_api", test_config: dict | None = None) -> None:
        self.config = load_config(typ=AMApiConfig, app_name=name, ns="api", test_config=test_config)
        super().__init__()
        self.context = Context(config=self.config)
        self.context.logger.info(f"Starting {name} app")


def init_api(name: str = "am_api", test_config: dict | None = None) -> AMAPI:
    app = AMAPI(name=name, test_config=test_config)
    app.router.route_class = ContextRequestRoute

    # Routers
    app.include_router(users_router)
    app.include_router(status_router)

    # Middleware
    app.add_middleware(AuthenticationMiddleware)

    # Exception handling
    # seems like there is a discussion about how to type exception handlers that was closed
    # https://github.com/encode/starlette/pull/1456
    app.add_exception_handler(RequestValidationError, validation_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(HTTPErrorDetail, http_error_detail_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, unexpected_error_handler)

    app.context.logger.info("app running...")
    return app
