from typing import Optional
from fastapi import FastAPI
from fastapi.routing import APIRoute

from eduid.common.config.parsers import load_config
from eduid.maccapi.config import MAccApiConfig
from eduid.maccapi.context import Context

from eduid.maccapi.routers.status import status_router
from eduid.maccapi.routers.users import users_router

class MAccAPI(FastAPI):
    def __init__(self, name: str="maccapi", test_config: Optional[dict] = None):
        self.config = load_config(typ=MAccApiConfig, app_name=name, ns="api", test_config=test_config)
        super().__init__(root_path=self.config.application_root)
        self.context = Context(config=self.config)
        self.context.logger.info(f"Starting {name} app")
        self.title = "maccapi"
        self.version = "1.0.0"

def init_api(name: str = "maccapi", test_config: Optional[dict] = None) -> MAccAPI:
    """
    Initialize the API.
    """
    app = MAccAPI(name=name, test_config=test_config)
    app.router.route_class = APIRoute

    app.include_router(status_router)
    app.include_router(users_router)

    app.context.logger.info("app running...")
    return app