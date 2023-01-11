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
from typing import Any, Dict, List

from flask import Blueprint

from eduid.webapp.common.api.decorators import MarshalWith
from eduid.webapp.common.api.messages import FluxData, success_response
from eduid.webapp.common.api.schemas.base import FluxStandardAction
from eduid.webapp.common.session import session
from eduid.webapp.jsconfig.app import current_jsconfig_app as current_app

jsconfig_views = Blueprint("jsconfig", __name__, url_prefix="")


def _fix_available_languages(available_languages: Dict[str, str]) -> List[List[str]]:
    # TODO: our frontend code should accept available_languages as map instead of list of lists
    return [[key, value] for key, value in available_languages.items()]


def _fix_uppercase_config(config: Dict[str, Any]):
    # XXX the front app consumes some settings as upper case and some as lower
    #   case. We'll provide them all in both upper and lower case, to
    #   facilitate migration of the front app to lower case.
    config_upper = {}
    for k, v in config.items():
        config_upper[k.upper()] = v
    config.update(config_upper)
    return config


# TODO: remove when /dashboard/config is used
@jsconfig_views.route("/config", methods=["GET"])
@MarshalWith(FluxStandardAction)
def get_dashboard_config_old() -> FluxData:
    return get_dashboard_config()


@jsconfig_views.route("/dashboard/config", methods=["GET"])
@MarshalWith(FluxStandardAction)
def get_dashboard_config() -> FluxData:
    """
    Configuration for the dashboard front app
    """
    config_dict = current_app.conf.jsapps.dict()
    config_dict["csrf_token"] = session.get_csrf_token()

    # Fixes for frontend
    if current_app.conf.fix_dashboard_available_languages:
        config_dict["available_languages"] = _fix_available_languages(current_app.conf.jsapps.available_languages)
    if current_app.conf.fix_dashboard_uppercase_config:
        config_dict = _fix_uppercase_config(config_dict)

    return success_response(payload=config_dict)


@jsconfig_views.route("/signup/config", methods=["GET"])
@MarshalWith(FluxStandardAction)
def get_signup_config() -> FluxData:
    """
    Configuration for the signup front app
    """
    config_dict = current_app.conf.jsapps.dict()
    config_dict["csrf_token"] = session.get_csrf_token()

    # Fixes for frontend
    if current_app.conf.fix_signup_available_languages:
        config_dict["available_languages"] = _fix_available_languages(current_app.conf.jsapps.available_languages)
    if current_app.conf.fix_signup_uppercase_config:
        config_dict = _fix_uppercase_config(config_dict)

    return success_response(payload=config_dict)


@jsconfig_views.route("/login/config", methods=["GET"])
@MarshalWith(FluxStandardAction)
def get_login_config() -> FluxData:
    """
    Configuration for the login front app
    """
    payload = {
        "base_url": current_app.conf.jsapps.login_base_url,  # OLD - remove when frontend is updated
        "login_base_url": current_app.conf.jsapps.login_base_url,  # NEW
        "csrf_token": session.get_csrf_token(),
        "dashboard_url": current_app.conf.jsapps.dashboard_url,
        "eduid_site_name": current_app.conf.jsapps.eduid_site_name,
        "eduid_site_url": current_app.conf.jsapps.eduid_site_url,
        "eidas_url": current_app.conf.jsapps.eidas_url,
        "environment": current_app.conf.jsapps.environment.value,
        "mfa_auth_idp": current_app.conf.jsapps.token_verify_idp,
        "next_url": current_app.conf.jsapps.login_next_url,
        "password_entropy": current_app.conf.jsapps.password_entropy,
        "password_length": current_app.conf.jsapps.password_length,
        "password_service_url": current_app.conf.jsapps.password_service_url,
        "request_other_url": current_app.conf.jsapps.request_other_url,
        "reset_password_url": current_app.conf.jsapps.reset_password_url,
        "sentry_dsn": current_app.conf.jsapps.sentry_dsn,
        "signup_url": current_app.conf.jsapps.signup_url,
    }
    return success_response(payload=payload)


@jsconfig_views.route("/errors/config", methods=["GET"])
@MarshalWith(FluxStandardAction)
def get_errors_config() -> FluxData:
    """
    Configuration for the errors front app
    """
    payload = {
        "csrf_token": session.get_csrf_token(),
        "dashboard_url": current_app.conf.jsapps.dashboard_url,
        "eduid_site_name": current_app.conf.jsapps.eduid_site_name,
        "eduid_site_url": current_app.conf.jsapps.eduid_site_url,
        "environment": current_app.conf.jsapps.environment.value,
        "error_info_url": current_app.conf.jsapps.error_info_url,
    }
    return success_response(payload=payload)
