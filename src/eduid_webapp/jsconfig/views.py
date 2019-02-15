# -*- coding: utf-8 -*-
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

from __future__ import absolute_import

from flask import Blueprint, session

from eduid_userdb.credentials import Webauthn
from eduid_common.config.parsers.etcd import EtcdConfigParser
from eduid_common.api.decorators import MarshalWith
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_webapp.jsconfig.settings.front import jsconfig


jsconfig_views = Blueprint('jsconfig', __name__, url_prefix='')

def get_webauthn_registration_options(user):
    user_webauthn_tokens = user.credentials.filter(Webauthn)
    if user_webauthn_tokens.count >= current_app.config['WEBAUTHN_MAX_ALLOWED_TOKENS']:
        current_app.logger.error('User tried to register more than {} tokens.'.format(
            current_app.config['WEBAUTHN_MAX_ALLOWED_TOKENS']))
        return {'_error': True, 'message': 'security.webauthn.max_allowed_tokens'}
    creds = make_credentials(user_webauthn_tokens.to_list())
    server = get_webauthn_server()
    registration_data, state = server.register_begin({
        'id': user.user_id,
        'name': user.surname,
        'displayName': user.display_name,
        'icon': ''
    }, creds)
    session['_webauthn_state_'] = state
    current_app.stats.count(name='webauthn_register_begin')
    return WebauthnBeginResponseSchema().load(registration_data).data

@jsconfig_views.route('/config', methods=['GET'])
@MarshalWith(FluxStandardAction)
def get_config():

    parser = EtcdConfigParser('/eduid/webapp/jsapps/')
    config = parser.read_configuration(silent=True)
    jsconfig.update(config)
    jsconfig['csrf_token'] = session.get_csrf_token()

    return jsconfig
