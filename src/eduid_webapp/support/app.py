# -*- coding: utf-8 -*-
#
# Copyright (c) 2019 SUNET
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
#     3. Neither the name of the SUNET nor the names of its
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

import operator
from typing import cast

from flask import current_app
from jinja2.exceptions import UndefinedError

from eduid_common.api.utils import urlappend
from eduid_common.authn.middleware import AuthnBaseApp
from eduid_userdb.support import db

from eduid_webapp.support.settings.common import SupportConfig


class SupportApp(AuthnBaseApp):
    def __init__(self, name: str, config: dict, **kwargs):
        # Initialise type of self.config before any parent class sets a precedent to mypy
        self.config = SupportConfig.init_config(ns='webapp', app_name=name, test_config=config)
        super().__init__(name, **kwargs)
        # cast self.config because sometimes mypy thinks it is a FlaskConfig after super().__init__()
        self.config: SupportConfig = cast(SupportConfig, self.config)  # type: ignore

        if self.config.token_service_url_logout is None:
            self.config.token_service_url_logout = urlappend(self.config.token_service_url, 'logout')

        from eduid_webapp.support.views import support_views

        self.register_blueprint(support_views)

        self.support_user_db = db.SupportUserDB(self.config.mongo_uri)
        self.support_authn_db = db.SupportAuthnInfoDB(self.config.mongo_uri)
        self.support_proofing_log_db = db.SupportProofingLogDB(self.config.mongo_uri)
        self.support_signup_db = db.SupportSignupUserDB(self.config.mongo_uri)
        self.support_actions_db = db.SupportActionsDB(self.config.mongo_uri)
        self.support_letter_proofing_db = db.SupportLetterProofingDB(self.config.mongo_uri)
        self.support_oidc_proofing_db = db.SupportOidcProofingDB(self.config.mongo_uri)
        self.support_email_proofing_db = db.SupportEmailProofingDB(self.config.mongo_uri)
        self.support_phone_proofing_db = db.SupportPhoneProofingDB(self.config.mongo_uri)

        register_template_funcs(self)


current_support_app: SupportApp = cast(SupportApp, current_app)


def register_template_funcs(app: SupportApp) -> None:
    @app.template_filter('datetimeformat')
    def datetimeformat(value, format='%Y-%m-%d %H:%M %Z'):
        if not value:
            return ''
        return value.strftime(format)

    @app.template_filter('multisort')
    def sort_multi(l, *operators, **kwargs):
        # Don't try to sort on missing keys
        keys = list(operators)  # operators is immutable
        for key in operators:
            for item in l:
                if key not in item:
                    app.logger.debug('Removed key {} before sorting.'.format(key))
                    keys.remove(key)
                    break
        reverse = kwargs.pop('reverse', False)
        try:
            l.sort(key=operator.itemgetter(*keys), reverse=reverse)
        except UndefinedError:  # attribute did not exist
            l = list()
        return l

    return None


def support_init_app(name: str, config: dict) -> SupportApp:
    """
    Create an instance of an eduid support app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases
    """

    app = SupportApp(name, config)

    app.logger.info(f'Init {name} app...')

    return app
