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

from eduid_common.api import am, msg
from eduid_common.authn.middleware import AuthnBaseApp
from eduid_userdb.logs import ProofingLog
from eduid_userdb.proofing import LookupMobileProofingUserDB

from eduid_webapp.lookup_mobile_proofing import lookup_mobile_relay
from eduid_webapp.lookup_mobile_proofing.settings.common import MobileProofingConfig

__author__ = 'lundberg'


class MobileProofingApp(AuthnBaseApp):
    def __init__(self, name: str, config: dict, **kwargs):
        # Initialise type of self.config before any parent class sets a precedent to mypy
        self.config = MobileProofingConfig.init_config(ns='webapp', app_name=name, test_config=config)
        super().__init__(name, **kwargs)
        # cast self.config because sometimes mypy thinks it is a FlaskConfig after super().__init__()
        self.config: MobileProofingConfig = cast(MobileProofingConfig, self.config)  # type: ignore

        # Register views
        from eduid_webapp.lookup_mobile_proofing.views import mobile_proofing_views

        self.register_blueprint(mobile_proofing_views)

        # Init dbs
        self.private_userdb = LookupMobileProofingUserDB(self.config.mongo_uri)
        self.proofing_log = ProofingLog(self.config.mongo_uri)

        # Init celery
        lookup_mobile_relay.init_relay(self)
        msg.init_relay(self)
        am.init_relay(self, 'eduid_lookup_mobile_proofing')


current_mobilep_app: MobileProofingApp = cast(MobileProofingApp, current_app)


def init_lookup_mobile_proofing_app(name: str, config: dict) -> MobileProofingApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases
    """

    app = MobileProofingApp(name, config)

    app.logger.info(f'Init {name} app...')

    return app
