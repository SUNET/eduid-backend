from flask import Blueprint, abort

from eduid.webapp.common.api.decorators import MarshalWith
from eduid.webapp.common.api.messages import FluxData, success_response
from eduid.webapp.common.api.schemas.base import FluxStandardAction
from eduid.webapp.common.session import session
from eduid.webapp.jsconfig.app import current_jsconfig_app as current_app

jsconfig_views = Blueprint("jsconfig", __name__, url_prefix="")


@jsconfig_views.route("/config", methods=["GET"])
@MarshalWith(FluxStandardAction)
def get_config() -> FluxData:
    """
    Configuration for the dashboard front app
    """

    config_dict = current_app.conf.jsapps.model_dump(mode="json")
    config_dict["csrf_token"] = session.get_csrf_token()

    return success_response(payload=config_dict)


@jsconfig_views.route("/<frontend_app>/config", methods=["GET"])
@MarshalWith(FluxStandardAction)
def get_config_for(frontend_app: str) -> FluxData:
    """
    Configuration for the dashboard front app
    """
    if frontend_app in ["dashboard", "signup", "login", "errors"]:
        current_app.logger.info(f"requesting config for frontend app {frontend_app}")
        return get_config()
    current_app.logger.error(f"{frontend_app} not in the list of supported apps")
    abort(404)
