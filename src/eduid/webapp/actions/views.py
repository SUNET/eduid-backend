# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
# Copyright (c) 2018 SUNET
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


import json
from urllib.parse import urlsplit, urlunsplit

from flask import Blueprint, abort, redirect, render_template, request, url_for
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.userdb.actions import Action
from eduid.webapp.actions.app import current_actions_app as current_app
from eduid.webapp.actions.helpers import ActionsMsg, get_next_action
from eduid.webapp.actions.schemas import PostActionRequestSchema, PostActionResponseSchema
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.base import FluxStandardAction
from eduid.webapp.common.authn.utils import check_previous_identification
from eduid.webapp.common.session import session

actions_views = Blueprint("actions", __name__, url_prefix="", template_folder="templates")


@actions_views.route("/", methods=["GET"])
def authn():
    """
    Check that the user was sent here by the IdP.
    """
    eppn = check_previous_identification(session.actions)
    if eppn is None:
        current_app.logger.error(f"Action authentication failed (eppn: {eppn}")
        return render_template("error.html")
    current_app.logger.info(f"Starting pre-login actions for eppn: {eppn}")
    url = url_for("actions.get_actions")
    return render_template("index.html", url=url)


@actions_views.route("/config", methods=["GET"])
@MarshalWith(FluxStandardAction)
def get_config():
    action_type = session.actions.current_plugin
    if not action_type:
        abort(403)
    plugin_obj = current_app.plugins[action_type]()
    try:
        config = plugin_obj.get_config_for_bundle(session.actions.current_action)
        config["csrf_token"] = session.new_csrf_token()
        return config
    except plugin_obj.ActionError as exc:
        return error_response(message=exc.args[0])


@actions_views.route("/get-actions", methods=["GET"])
def get_actions():
    user = current_app.central_userdb.get_user_by_eppn(session.common.eppn)
    actions = get_next_action(user)
    if not actions["action"]:
        return json.dumps(
            {"action": False, "url": actions["idp_url"], "payload": {"csrf_token": session.new_csrf_token()}}
        )
    plugin_obj = current_app.plugins[session.actions.current_plugin]()
    action = session.actions.current_action
    if not action:
        # please mypy
        abort(500)
    current_app.logger.info(f"Starting pre-login action {action.action_type} for user {user}")
    try:
        url = plugin_obj.get_url_for_bundle(action)
        return json.dumps({"action": True, "url": url, "payload": {"csrf_token": session.new_csrf_token()}})
    except plugin_obj.ActionError as exc:
        _aborted(action, exc)
        abort(500)


@actions_views.route("/post-action", methods=["POST"])
@MarshalWith(PostActionResponseSchema)
@UnmarshalWith(PostActionRequestSchema)
def post_action() -> FluxData:
    return _do_action()


@actions_views.route("/redirect-action", methods=["GET"])
def redirect_action() -> WerkzeugResponse:
    # Setup a redirect url to action app root
    scheme, netloc, path, query_string, fragment = urlsplit(request.url)
    path = url_for("actions.authn")
    return_url = urlunsplit((scheme, netloc, path, query_string, fragment))
    # TODO: Look in ret to figure out if we need to add a query string with a user message
    _ = _do_action()
    return redirect(return_url)


def _do_action() -> FluxData:
    action_type = session.actions.current_plugin
    if not action_type:
        abort(403)

    plugin_obj = current_app.plugins[action_type]()
    action = session.actions.current_action
    if not action:
        raise ValueError("No current action found in session")
    try:
        data = plugin_obj.perform_step(action)
    except plugin_obj.ActionError as exc:
        return _aborted(action, exc)
    except plugin_obj.ValidationError as exc:
        errors = exc.args[0]
        current_app.logger.info(f"Validation error {errors} for step {session.actions.current_step} of action {action}")
        # TODO: Really decrease current_step here, even though we haven't increased it yet?
        if session.actions.current_step is not None:
            session.actions.current_step -= 1
        return error_response(payload={"errors": errors}, message=CommonMsg.form_errors)

    eppn = session.common.eppn
    if session.actions.total_steps == session.actions.current_step:
        current_app.logger.info(f"Finished pre-login action {action.action_type} for eppn {eppn}")
        return success_response(payload=dict(data=data), message=ActionsMsg.action_completed)

    current_app.logger.info(
        "Performed step {} for action {} for eppn {}".format(action.action_type, session.actions.current_step, eppn)
    )
    if session.actions.current_step is not None:
        session.actions.current_step += 1
    return success_response(payload={"data": data}, message=None)


def _aborted(action: Action, exc) -> FluxData:
    eppn = session.common.eppn
    current_app.logger.info(f"Aborted pre-login action {action.action_type} for eppn {eppn}, reason: {exc.args[0]}")
    if exc.remove_action:
        current_app.logger.info(f"Removing faulty action with id {action.action_id}")
        current_app.actions_db.remove_action_by_id(action.action_id)
    return error_response(message=exc.args[0])
