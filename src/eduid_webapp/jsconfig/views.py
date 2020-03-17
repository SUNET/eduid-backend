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
from dataclasses import asdict
from typing import Dict, Optional, cast

import requests
from flask import Blueprint, abort, render_template, request

from eduid_common.api.decorators import MarshalWith
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_common.config.exceptions import BadConfiguration
from eduid_common.config.parsers.etcd import EtcdConfigParser, etcd
from eduid_common.session import session

from eduid_webapp.jsconfig.app import current_jsconfig_app as current_app
from eduid_webapp.jsconfig.settings.front import FrontConfig

jsconfig_views = Blueprint('jsconfig', __name__, url_prefix='', template_folder='templates')


CACHE = {}


def get_etcd_config(namespace: Optional[str] = None) -> FrontConfig:
    if namespace is None:
        namespace = '/eduid/webapp/jsapps/'
    parser = EtcdConfigParser(namespace)
    config = parser.read_configuration(silent=False)
    config = {k.lower(): v for k, v in config.items()}
    return FrontConfig(**config)


@jsconfig_views.route('/config', methods=['GET'], subdomain="dashboard")
@MarshalWith(FluxStandardAction)
def get_dashboard_config() -> dict:
    """
    Configuration for the dashboard front app
    """
    try:
        config: Optional[FrontConfig] = get_etcd_config()
        CACHE['dashboard_config'] = config
    except etcd.EtcdConnectionFailed as e:
        current_app.logger.warning(f'No connection to etcd: {e}')
        config = CACHE.get('dashboard_config')
    if config is None:
        raise BadConfiguration('Configuration not found')
    config.csrf_token = session.get_csrf_token()
    # XXX the front app consumes some settings as upper case and some as lower
    # case. We'll provide them all in both upper and lower case, to
    # possibilitate migration of the front app - preferably to lower case.
    config_dict = asdict(config)
    config_upper = {}
    for k, v in config_dict.items():
        config_upper[k.upper()] = v
    config_dict.update(config_upper)
    return config_dict


@jsconfig_views.route('/signup/config', methods=['GET'], subdomain="signup")
@MarshalWith(FluxStandardAction)
def get_signup_config() -> dict:
    """
    Configuration for the signup front app
    """
    if not current_app.config.tou_url:
        raise BadConfiguration('tou_url not set')
    tou_url = current_app.config.tou_url
    # Get config from etcd
    try:
        config: Optional[FrontConfig] = get_etcd_config()
        CACHE['signup_config'] = config
    except etcd.EtcdConnectionFailed as e:
        current_app.logger.warning(f'No connection to etcd: {e}')
        current_app.logger.info('Serving cached config')
        config = CACHE.get('signup_config')
    # Get ToUs from the ToU action
    if config is None:
        raise BadConfiguration('Configuration not found')
    tous = None
    try:
        r = requests.get(tou_url)
        current_app.logger.debug('Response: {!r} with headers: {!r}'.format(r, r.headers))
        if r.status_code == 302:
            headers = {'Cookie': r.headers.get('Set-Cookie')}
            current_app.logger.debug('Headers: {}'.format(headers))
            r = requests.get(tou_url, headers=headers)
            current_app.logger.debug('2nd response: {!r} with headers: {}'.format(r, r.headers))
            if r.status_code != 200:
                current_app.logger.debug('Problem getting config, response status: {}'.format(r.status_code))
                abort(500)
        tous = r.json()['payload']
        CACHE['tous'] = tous
    except requests.exceptions.HTTPError as e:
        current_app.logger.warning('Problem getting tous from URL {!r}: {!r}'.format(tou_url, e))
        tous = CACHE.get('tous')

    if tous is None:
        abort(500)

    config.debug = current_app.config.debug
    config.csrf_token = session.get_csrf_token()
    config.tous = cast(Dict[str, str], tous)
    # XXX the front app consumes some settings as upper case and some as lower
    # case. We'll provide them all in both upper and lower case, to
    # possibilitate migration of the front app - preferably to lower case.
    config_dict = asdict(config)
    config_upper = {}
    for k, v in config_dict.items():
        config_upper[k.upper()] = v
    config_dict.update(config_upper)
    return config_dict


@jsconfig_views.route('/login/config', methods=['GET'], subdomain="login")
@MarshalWith(FluxStandardAction)
def get_login_config() -> dict:
    """
    Configuration for the login front app
    """
    current_app.logger.info(f'Serving configuration for the login app')

    config = get_etcd_config()
    return {
        'csrf_token': session.get_csrf_token(),
        'password_service_url': config.password_service_url,
        'password_entropy': config.password_entropy,
        'password_length': config.password_length,
    }


@jsconfig_views.route('/get-bundle', methods=['GET'], subdomain="dashboard")
def get_dashboard_bundle():
    context = {
        'bundle': current_app.config.dashboard_bundle_path,
        'version': current_app.config.dashboard_bundle_version,
    }
    feature_cookie = request.cookies.get(current_app.config.dashboard_bundle_feature_cookie)
    if feature_cookie and feature_cookie in current_app.config.dashboard_bundle_feature_version:
        context['version'] = current_app.config.dashboard_bundle_feature_version[feature_cookie]
    try:
        return render_template('load_bundle.jinja2', context=context)
    except AttributeError as e:
        current_app.logger.error(f'Template rendering failed: {e}')
        abort(500)


@jsconfig_views.route('/get-bundle', methods=['GET'], subdomain="signup")
def get_signup_bundle():
    context = {
        'bundle': current_app.config.signup_bundle_path,
        'version': current_app.config.signup_bundle_version,
    }
    feature_cookie = request.cookies.get(current_app.config.signup_bundle_feature_cookie)
    if feature_cookie and feature_cookie in current_app.config.signup_bundle_feature_version:
        context['version'] = current_app.config.signup_bundle_feature_version[feature_cookie]
    try:
        return render_template('load_bundle.jinja2', context=context)
    except AttributeError as e:
        current_app.logger.error(f'Template rendering failed: {e}')
        abort(500)


@jsconfig_views.route('/get-bundle', methods=['GET'], subdomain="login")
def get_login_bundle():
    context = {
        'bundle': current_app.config.login_bundle_path,
        'version': current_app.config.login_bundle_version,
    }
    feature_cookie = request.cookies.get(current_app.config.login_bundle_feature_cookie)
    if feature_cookie and feature_cookie in current_app.config.login_bundle_feature_version:
        context['version'] = current_app.config.login_bundle_feature_version[feature_cookie]
    try:
        return render_template('load_bundle.jinja2', context=context)
    except AttributeError as e:
        current_app.logger.error(f'Template rendering failed: {e}')
        abort(500)
