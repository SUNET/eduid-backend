from typing import Optional

from fastapi import FastAPI

from eduid.common.config.parsers import load_config
from eduid.maccapi.config import MAccApiConfig
from eduid.maccapi.context import Context
from eduid.maccapi.context_request import ContextRequestRoute
from eduid.maccapi.middleware import AuthenticationMiddleware
from eduid.maccapi.routers.status import status_router
from eduid.maccapi.routers.users import users_router
from eduid.vccs.client import VCCSClient


class MAccAPI(FastAPI):
    def __init__(
        self, name: str = "maccapi", test_config: Optional[dict] = None, vccs_client: Optional[VCCSClient] = None
    ):
        self.config = load_config(typ=MAccApiConfig, app_name=name, ns="api", test_config=test_config)
        super().__init__(root_path=self.config.application_root)
        self.context = Context(config=self.config, vccs_client=vccs_client)
        self.context.logger.info(f"Starting {name} app")


def init_api(
    name: str = "maccapi", test_config: Optional[dict] = None, vccs_client: Optional[VCCSClient] = None
) -> MAccAPI:
    """
    Initialize the API.
    """
    app = MAccAPI(name=name, test_config=test_config, vccs_client=vccs_client)
    app.router.route_class = ContextRequestRoute

    app.include_router(status_router)
    app.include_router(users_router)

    app.add_middleware(AuthenticationMiddleware, context=app.context)

    app.context.logger.info("app running...")
    return app
