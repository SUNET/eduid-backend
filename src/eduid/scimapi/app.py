from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.middleware.cors import CORSMiddleware

from eduid.common.config.parsers import load_config
from eduid.scimapi.config import ScimApiConfig
from eduid.scimapi.context import Context
from eduid.scimapi.context_request import ScimApiRoute
from eduid.scimapi.exceptions import (
    HTTPErrorDetail,
    http_error_detail_handler,
    unexpected_error_handler,
    validation_exception_handler,
)
from eduid.scimapi.middleware import AuthenticationMiddleware, ScimMiddleware
from eduid.scimapi.routers.events import events_router
from eduid.scimapi.routers.groups import groups_router
from eduid.scimapi.routers.invites import invites_router
from eduid.scimapi.routers.login import login_router
from eduid.scimapi.routers.status import status_router
from eduid.scimapi.routers.users import users_router


class ScimAPI(FastAPI):
    def __init__(self, name: str = "scimapi", test_config: dict | None = None) -> None:
        self.config = load_config(typ=ScimApiConfig, app_name=name, ns="api", test_config=test_config)
        super().__init__(root_path=self.config.application_root)
        self.context = Context(config=self.config)
        self.context.logger.info(f"Starting {name} app")


def init_api(name: str = "scimapi", test_config: dict | None = None) -> ScimAPI:
    app = ScimAPI(name=name, test_config=test_config)
    app.router.route_class = ScimApiRoute

    # Routers
    # TODO: Move bearer token generation to a separate API
    app.include_router(login_router, include_in_schema=app.config.login_enabled)
    app.include_router(users_router)
    app.include_router(groups_router)
    app.include_router(invites_router)
    app.include_router(events_router)
    app.include_router(status_router)

    # Middleware
    app.add_middleware(AuthenticationMiddleware, context=app.context)
    app.add_middleware(ScimMiddleware, context=app.context)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Exception handling
    # seems like there is a discussion about how to type exception handlers that was closed
    # https://github.com/encode/starlette/pull/1456
    app.add_exception_handler(RequestValidationError, validation_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(HTTPErrorDetail, http_error_detail_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, unexpected_error_handler)

    app.context.logger.info("app running...")
    return app
