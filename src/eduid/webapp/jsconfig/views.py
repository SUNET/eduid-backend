#
# Copyright (c) 2016 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

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

    config_dict = current_app.conf.jsapps.dict()
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
