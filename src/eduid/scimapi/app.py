from typing import Dict, Optional

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from eduid.common.config.parsers import load_config
from eduid.scimapi.config import ScimApiConfig
from eduid.scimapi.context import Context
from eduid.scimapi.context_request import ContextRequestRoute
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
    def __init__(self, name: str = 'scimapi', test_config: Optional[Dict] = None):
        super().__init__()
        self.config = load_config(typ=ScimApiConfig, app_name=name, ns='api', test_config=test_config)
        self.context = Context(config=self.config)
        self.context.logger.info(f'Starting {name} app')


def init_api(name: str = 'scimapi', test_config: Optional[Dict] = None) -> ScimAPI:
    app = ScimAPI(name=name, test_config=test_config)
    app.router.route_class = ContextRequestRoute

    # Routers
    # TODO: Move bearer token generation to a separate API
    app.include_router(login_router)
    app.include_router(users_router)
    app.include_router(groups_router)
    app.include_router(invites_router)
    app.include_router(events_router)
    app.include_router(status_router)

    # Middleware
    app.add_middleware(AuthenticationMiddleware, context=app.context)
    app.add_middleware(ScimMiddleware, context=app.context)

    # Exception handling
    app.add_exception_handler(StarletteHTTPException, unexpected_error_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(HTTPErrorDetail, http_error_detail_handler)

    app.context.logger.info('app running...')
    return app
