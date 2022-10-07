import logging
from typing import Any, Dict, List, Optional, Union

from fastapi import FastAPI

from eduid.common.config.parsers import load_config
from eduid.common.fastapi.exceptions import (
    HTTPErrorDetail,
    RequestValidationError,
    http_error_detail_handler,
    unexpected_error_handler,
    validation_exception_handler,
)
from eduid.common.logging import init_logging
from eduid.userdb import AmDB, UserDB
from eduid.userdb.logs.db import UserChangeLog
from eduid.workers.amapi.config import AMApiConfig
from eduid.workers.amapi.context_request import ContextRequestRoute
from eduid.workers.amapi.middleware import AuthenticationMiddleware
from eduid.workers.amapi.routers.status import status_router
from eduid.workers.amapi.routers.users import users_router
from eduid.workers.amapi.utils import load_jwks


class AMAPI(FastAPI):
    def __init__(self, name: str = "am_api", test_config: Optional[Dict] = None):
        self.config = load_config(typ=AMApiConfig, app_name=name, ns="api", test_config=test_config)
        super().__init__(root_path=self.config.application_root)

        self.db = AmDB(db_uri=self.config.mongo_uri)
        self.name = "am_api"

        self.logger = logging.getLogger(name="am_api")
        init_logging(config=self.config)
        self.logger.info(f"Starting {name} app")
        self.audit_logger = UserChangeLog(self.config.mongo_uri)

        self.jwks = load_jwks(self.config)


def init_api(name: str = "am_api", test_config: Optional[Dict] = None) -> AMAPI:
    app = AMAPI(name=name, test_config=test_config)
    app.router.route_class = ContextRequestRoute

    # Routers
    app.include_router(users_router)
    app.include_router(status_router)

    # Middleware
    # app.add_middleware(AuthenticationMiddleware)

    # Exception handling
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(HTTPErrorDetail, http_error_detail_handler)
    app.add_exception_handler(Exception, unexpected_error_handler)

    app.logger.info("app running...")
    return app
