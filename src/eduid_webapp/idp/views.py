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

from eduid_common.api.decorators import require_user
from eduid_webapp.idp.app import current_idp_app as current_app
from werkzeug.exceptions import Forbidden
from werkzeug.wrappers import Response as WerkzeugResponse


__author__ = 'ft'

from eduid_webapp.idp.login import SSO, do_verify
from eduid_webapp.idp.logout import SLO

idp_views = Blueprint('idp', __name__, url_prefix='', template_folder='templates')


@idp_views.route('/', methods=['GET'])
def index() -> WerkzeugResponse:
    return redirect(current_app.config.eduid_site_url)


@idp_views.route('/sso/post', methods=['POST'])
def sso_post(*_args, **_kwargs):
    current_app.logger.debug(f'SingleSignOn post: {request.path}')
    sso_session = current_app._lookup_sso_session()
    return SSO(sso_session, current_app.context).post()


@idp_views.route('/sso/redirect', methods=['GET'])
def sso_redirect(*_args, **_kwargs):
    current_app.logger.debug(f'SingleSignOn redirect: {request.path}')
    sso_session = current_app._lookup_sso_session()
    return SSO(sso_session, current_app.context).redirect()


@idp_views.route('/slo/post', methods=['POST'])
def slo_post(*_args, **_kwargs):
    current_app.logger.debug(f'SingleLogOut post: {request.path}')
    sso_session = current_app._lookup_sso_session()
    return SLO(sso_session, current_app.context).post()


@idp_views.route('/slo/redirect', methods=['GET'])
def slo_redirect(*_args, **_kwargs):
    current_app.logger.debug(f'SingleLogOut redirect: {request.path}')
    slo_session = current_app._lookup_sso_session()
    return SLO(slo_session, current_app.context).redirect()


@idp_views.route('/verify', methods=['POST'])
def verify(*_args, **_kwargs):
    current_app.logger.debug("\n\n")
    current_app.logger.debug("--- Verify ---")
    if current_app._lookup_sso_session():
        # If an already logged in user presses 'back' or similar, we can't really expect to
        # manage to log them in again (think OTPs) and just continue 'back' to the SP.
        # However, with forceAuthn, this is exactly what happens so maybe it isn't really
        # an error case.
        # raise eduid_idp.error.LoginTimeout("Already logged in - can't verify credentials again",
        #                                   logger = self.logger)
        current_app.logger.debug("User is already logged in - verifying credentials again might not work")
    return do_verify(current_app.context)
