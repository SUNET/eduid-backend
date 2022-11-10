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

from flask import Blueprint, redirect, request
from werkzeug.exceptions import BadRequest
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.messages import FluxData, success_response
from eduid.webapp.common.session.namespaces import RequestRef
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.decorators import require_ticket
from eduid.webapp.idp.login import do_verify, get_ticket, show_login_page
from eduid.webapp.idp.login_context import LoginContext, LoginContextSAML

__author__ = "ft"

from eduid.webapp.idp.mischttp import parse_query_string
from eduid.webapp.idp.schemas import AbortRequestSchema, AbortResponseSchema
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
