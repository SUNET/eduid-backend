from fastapi import FastAPI
from typing import Any, Dict, List, Optional, Union

from eduid.common.config.parsers import load_config
from eduid.workers.amapi.config import AMApiConfig
from eduid.workers.amapi.context_request import ContextRequestRoute
from eduid.workers.amapi.exceptions import (
    HTTPErrorDetail,
    http_error_detail_handler,
    unexpected_error_handler,
 #   validation_exception_handler,
)
from eduid.workers.amapi.middleware import AuthenticationMiddleware
from fastapi.exceptions import RequestValidationError
from eduid.workers.amapi.routers.status import status_router
from eduid.workers.amapi.routers.users import users_router
from eduid.workers.amapi.routers.sampler import sampler_router
from eduid.common.logging import init_logging
import logging
from eduid.userdb.amapi.db import AMApiDB
from eduid.workers.amapi.utils import load_jwks


class AMAPI(FastAPI):
    def __init__(self, name: str = 'amapi', test_config: Optional[Dict] = None):
        self.config = load_config(typ=AMApiConfig, app_name=name, ns='api', test_config=test_config)
        super().__init__(root_path=self.config.application_root)

        self.db = AMApiDB(db_uri=self.config.mongo_uri)
        self.name = "amapi"

        self.logger = logging.getLogger(name='amapi')
        init_logging(config=self.config)
        self.logger.info(f'Starting {name} app')

        self.jwks = load_jwks(self.config)


def init_api(name: str = 'amapi', test_config: Optional[Dict] = None) -> AMAPI:
    app = AMAPI(name=name, test_config=test_config)
    app.router.route_class = ContextRequestRoute

    # Routers
    app.include_router(users_router)
    app.include_router(status_router)
    app.include_router(sampler_router)

    # Middleware
    app.add_middleware(AuthenticationMiddleware)

    # Exception handling
   # app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(HTTPErrorDetail, http_error_detail_handler)
    app.add_exception_handler(Exception, unexpected_error_handler)

    app.logger.info('app running...')
    return app