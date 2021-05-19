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

from eduid.webapp.common.session.namespaces import ReqSHA1
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.login import SSO, do_verify, get_ticket, show_login_page
from eduid.webapp.idp.logout import SLO

__author__ = 'ft'

from eduid.webapp.idp.mischttp import parse_query_string
from eduid.webapp.idp.service import SAMLQueryParams

idp_views = Blueprint('idp', __name__, url_prefix='', template_folder='templates')


@idp_views.route('/', methods=['GET'])
def index() -> WerkzeugResponse:
    return redirect(current_app.conf.eduid_site_url)


@idp_views.route('/sso/post', methods=['POST'])
def sso_post() -> WerkzeugResponse:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- SingleSignOn POST: {request.path} ---')
    sso_session = current_app._lookup_sso_session()
    return SSO(sso_session).post()


@idp_views.route('/sso/redirect', methods=['GET'])
def sso_redirect() -> WerkzeugResponse:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- SingleSignOn REDIRECT: {request.path} ---')
    sso_session = current_app._lookup_sso_session()
    return SSO(sso_session).redirect()


@idp_views.route('/slo/post', methods=['POST'])
def slo_post() -> WerkzeugResponse:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- SingleLogOut POST: {request.path} ---')
    sso_session = current_app._lookup_sso_session()
    return SLO(sso_session).post()


@idp_views.route('/slo/soap', methods=['POST'])
def slo_soap() -> WerkzeugResponse:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- SingleLogOut SOAP: {request.path} ---')
    sso_session = current_app._lookup_sso_session()
    return SLO(sso_session).soap()


@idp_views.route('/slo/redirect', methods=['GET'])
def slo_redirect() -> WerkzeugResponse:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- SingleLogOut REDIRECT: {request.path} ---')
    slo_session = current_app._lookup_sso_session()
    return SLO(slo_session).redirect()


@idp_views.route('/verify', methods=['GET', 'POST'])
def verify() -> WerkzeugResponse:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f"--- Verify ({request.method}) ---")

    if request.method == 'GET':
        query = parse_query_string()
        if 'key' not in query:
            raise BadRequest(f'Missing parameter key - please re-initiate login')
        _info = SAMLQueryParams(key=ReqSHA1(query['key']))
        ticket = get_ticket(_info, None)
        return show_login_page(ticket)

    if request.method == 'POST':
        if current_app._lookup_sso_session():
            # If an already logged in user presses 'back' or similar, we can't really expect to
            # manage to log them in again (think OTPs) and just continue 'back' to the SP.
            # However, with forceAuthn, this is exactly what happens so maybe it isn't really
            # an error case.
            # raise eduid_idp.error.LoginTimeout("Already logged in - can't verify credentials again",
            #                                   logger = self.logger)
            current_app.logger.debug("User is already logged in - verifying credentials again might not work")
        return do_verify()

    raise BadRequest()
