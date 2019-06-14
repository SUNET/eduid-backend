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
from typing import Optional

import requests
from eduid_common.api.decorators import MarshalWith
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_common.config.parsers.etcd import etcd, EtcdConfigParser
from eduid_common.session import session
from flask import Blueprint, current_app, render_template, abort

from eduid_webapp.jsconfig.settings.front import dashboard_config, signup_config

jsconfig_views = Blueprint('jsconfig', __name__, url_prefix='', template_folder='templates')

CACHE = {}


def get_etcd_config(default_config: dict, namespace: Optional[str] = None) -> dict:
    if namespace is None:
        namespace = '/eduid/webapp/jsapps/'
    parser = EtcdConfigParser(namespace)
    config = parser.read_configuration(silent=False)
    default_config.update(config)
    return default_config


@jsconfig_views.route('/config', methods=['GET'], subdomain="dashboard")
@MarshalWith(FluxStandardAction)
def get_dashboard_config() -> dict:
    try:
        config = get_etcd_config(dashboard_config)
        CACHE['dashboard_config'] = config
    except etcd.EtcdConnectionFailed as e:
        current_app.logger.warning(f'No connection to etcd: {e}')
        config = CACHE.get('dashboard_config', {})
    config['csrf_token'] = session.get_csrf_token()
    return config




@jsconfig_views.route('/get-bundle', methods=['GET'], subdomain="dashboard")
def get_dashboard_bundle():
    context = {
        'bundle': current_app.config.get('DASHBOARD_BUNDLE_PATH'),
        'version': current_app.config.get('DASHBOARD_BUNDLE_VERSION'),
    }
    try:
        return render_template('load_bundle.jinja2', context=context)
    except AttributeError as e:
        current_app.logger.error(f'Template rendering failed: {e}')
        abort(500)


@jsconfig_views.route('/get-bundle', methods=['GET'], subdomain="signup")
def get_signup_bundle():
    context = {
        'bundle': current_app.config.get('SIGNUP_BUNDLE_PATH'),
        'version': current_app.config.get('SIGNUP_BUNDLE_VERSION'),
    }
    try:
        return render_template('load_bundle.jinja2', context=context)
    except AttributeError as e:
        current_app.logger.error(f'Template rendering failed: {e}')
        abort(500)
