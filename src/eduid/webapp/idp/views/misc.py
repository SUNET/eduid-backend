# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 SUNET
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

from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, redirect, request
from werkzeug.exceptions import BadRequest
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.messages import FluxData, success_response
from eduid.webapp.common.api.schemas.models import FluxSuccessResponse
from eduid.webapp.common.session.namespaces import IdP_SAMLPendingRequest, RequestRef
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.decorators import require_ticket, uses_sso_session
from eduid.webapp.idp.login import do_verify, get_ticket, show_login_page
from eduid.webapp.idp.login_context import LoginContext, LoginContextSAML
from eduid.webapp.idp.service import SAMLQueryParams
from eduid.webapp.idp.sso_session import SSOSession, session

__author__ = "ft"

from eduid.webapp.idp.mischttp import parse_query_string
from eduid.webapp.idp.schemas import AbortRequestSchema, AbortResponseSchema, LogoutRequestSchema, LogoutResponseSchema
from eduid.webapp.idp.service import SAMLQueryParams

misc_views = Blueprint("misc", __name__, url_prefix="", template_folder="../templates")


@misc_views.route("/", methods=["GET"])
def index() -> WerkzeugResponse:
    return redirect(current_app.conf.eduid_site_url)


@misc_views.route("/abort", methods=["POST"])
@UnmarshalWith(AbortRequestSchema)
@MarshalWith(AbortResponseSchema)
@require_ticket
def abort(ticket: LoginContext) -> FluxData:
    """Abort the current request"""
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- Abort ({ticket.request_ref}) ---")

    ticket.pending_request.aborted = True

    return success_response(payload={"finished": True})


@misc_views.route("/logout", methods=["POST"])
@UnmarshalWith(LogoutRequestSchema)
@MarshalWith(LogoutResponseSchema)
@uses_sso_session
def logout(ref: Optional[str], sso_session: Optional[SSOSession]) -> FluxData:
    """Logout from the current SSO session"""
    current_app.logger.debug("\n\n")
    _session_id = sso_session.session_id if sso_session else None
    current_app.logger.debug(f"--- Logout ({_session_id}) ---")
    current_app.logger.debug(f"SSO session: {sso_session})")

    if sso_session:
        _res = current_app.sso_sessions.remove_session(sso_session)
        current_app.logger.debug(f"Removed SSO session {sso_session} from the database: {_res}")

    location = None
    ticket = None
    old_saml_req: Optional[IdP_SAMLPendingRequest] = None
    _ref = None
    if ref:
        _info = SAMLQueryParams(request_ref=ref)
        ticket = get_ticket(_info, None)

    if isinstance(ticket, LoginContextSAML):
        # If the user is logging in to an entity ID for which we have a finish URL, we want the frontend
        # to redirect them there. For the unknown third party case, we migrate the ongoing SAML request
        # to the new session.
        _entity_id = ticket.saml_req.sp_entity_id
        if _entity_id in current_app.conf.logout_finish_url:
            location = current_app.conf.logout_finish_url[_entity_id]
            current_app.logger.debug(f"Will ask frontend to redirect user to {location} for entity ID {_entity_id}")
        else:
            current_app.logger.debug(f"Will retain SAML request in session for entity ID {_entity_id}")
            assert isinstance(ticket.pending_request, IdP_SAMLPendingRequest)  # please type checking
            old_saml_req = ticket.pending_request
            _ref = ticket.request_ref

    current_app.logger.debug(f"Resetting session: {session})")
    session.reset()

    if _ref and old_saml_req:
        session.idp.pending_requests[_ref] = IdP_SAMLPendingRequest(
            request=old_saml_req.request, binding=old_saml_req.binding, relay_state=old_saml_req.relay_state
        )

    payload: Dict[str, Any] = {"finished": True}
    if location:
        payload["location"] = location

    _flux_response = FluxSuccessResponse(request, payload=payload)
    resp: WerkzeugResponse = jsonify(LogoutResponseSchema().dump(_flux_response.to_dict()))

    # Delete the SSO session cookie in the browser
    resp.delete_cookie(
        key=current_app.conf.sso_cookie.key,
        path=current_app.conf.sso_cookie.path,
        domain=current_app.conf.sso_cookie.domain,
    )

    current_app.logger.debug(f"Cookies in logout response: {resp.headers.getlist('Set-Cookie')}")

    current_app.logger.info("User logged out")

    return resp


@misc_views.route("/verify", methods=["GET", "POST"])
def verify() -> WerkzeugResponse:
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- Verify ({request.method}) ---")

    if request.method == "GET":
        query = parse_query_string()
        if "ref" not in query:
            raise BadRequest(f"Missing parameter - please re-initiate login")
        _info = SAMLQueryParams(request_ref=RequestRef(query["ref"]))
        ticket = get_ticket(_info, None)
        if not ticket:
            raise BadRequest(f"Missing parameter - please re-initiate login")

        # TODO: Remove all this code, we don't use the template IdP anymore.
        if not current_app.conf.enable_legacy_template_mode:
            raise BadRequest("Template IdP not enabled")

        # please mypy with this legacy code
        assert isinstance(ticket, LoginContextSAML)

        return show_login_page(ticket)

    if request.method == "POST":
        return do_verify()

    raise BadRequest()
