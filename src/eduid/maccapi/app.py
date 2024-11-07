from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from eduid.common.config.parsers import load_config
from eduid.maccapi.config import MAccApiConfig
from eduid.maccapi.context import Context
from eduid.maccapi.context_request import MaccAPIRoute
from eduid.maccapi.middleware import AuthenticationMiddleware
from eduid.maccapi.routers.status import status_router
from eduid.maccapi.routers.users import users_router
from eduid.vccs.client import VCCSClient


class MAccAPI(FastAPI):
    def __init__(
        self, name: str = "maccapi", test_config: dict | None = None, vccs_client: VCCSClient | None = None
    ) -> None:
        self.config = load_config(typ=MAccApiConfig, app_name=name, ns="api", test_config=test_config)
        super().__init__(root_path=self.config.application_root)
        self.context = Context(config=self.config, vccs_client=vccs_client)
        self.context.logger.info(f"Starting {name} app")


def init_api(name: str = "maccapi", test_config: dict | None = None, vccs_client: VCCSClient | None = None) -> MAccAPI:
    """
    Initialize the API.
    """
    app = MAccAPI(name=name, test_config=test_config, vccs_client=vccs_client)
    app.router.route_class = MaccAPIRoute

    app.include_router(status_router)
    app.include_router(users_router)

    app.add_middleware(AuthenticationMiddleware, context=app.context)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.context.logger.info("app running...")
    return app
