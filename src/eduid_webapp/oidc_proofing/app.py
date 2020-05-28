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
from typing import cast

from flask import current_app

from eduid_common.api import am, mail_relay, msg, oidc, translation
from eduid_common.authn.middleware import AuthnBaseApp
from eduid_common.authn.utils import no_authn_views
from eduid_userdb.logs import ProofingLog
from eduid_userdb.proofing import OidcProofingStateDB, OidcProofingUserDB

from eduid_webapp.oidc_proofing.settings.common import OIDCProofingConfig

__author__ = 'lundberg'


class OIDCProofingApp(AuthnBaseApp):
    def __init__(self, name: str, config: dict, **kwargs):
        # Initialise type of self.config before any parent class sets a precedent to mypy
        self.config = OIDCProofingConfig.init_config(ns='webapp', app_name=name, test_config=config)
        super().__init__(name, **kwargs)
        # cast self.config because sometimes mypy thinks it is a FlaskConfig after super().__init__()
        self.config: OIDCProofingConfig = cast(OIDCProofingConfig, self.config)  # type: ignore

        from eduid_webapp.oidc_proofing.views import oidc_proofing_views

        self.register_blueprint(oidc_proofing_views)

        # Register view path that should not be authorized
        no_authn_views(self, ['/authorization-response'])

        # Initialize the oidc_client after views to be able to set correct redirect_uris
        oidc.init_client(self)

        # Init celery
        msg.init_relay(self)
        am.init_relay(self, 'eduid_oidc_proofing')
        mail_relay.init_relay(self)

        # Init babel
        translation.init_babel(self)

        # Initialize db
        self.private_userdb = OidcProofingUserDB(self.config.mongo_uri)
        self.proofing_statedb = OidcProofingStateDB(self.config.mongo_uri)
        self.proofing_log = ProofingLog(self.config.mongo_uri)


current_oidcp_app: OIDCProofingApp = cast(OIDCProofingApp, current_app)


def init_oidc_proofing_app(name: str, config: dict) -> OIDCProofingApp:
    """
    Create an instance of an oidc proofing app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases
    """

    app = OIDCProofingApp(name, config)

    app.logger.info(f'Init {name} app...')

    return app
