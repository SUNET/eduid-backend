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
from typing import Any, Mapping, Optional, cast

from flask import current_app

from eduid_common.api.am import AmRelay
from eduid_common.api.msg import MsgRelay
from eduid_common.authn.middleware import AuthnBaseApp
from eduid_common.config.parsers import load_config
from eduid_userdb.logs import ProofingLog
from eduid_userdb.proofing import LookupMobileProofingUserDB

from eduid_webapp.lookup_mobile_proofing.lookup_mobile_relay import LookupMobileRelay
from eduid_webapp.lookup_mobile_proofing.settings.common import MobileProofingConfig

__author__ = 'lundberg'


class MobileProofingApp(AuthnBaseApp):
    def __init__(self, config: MobileProofingConfig, **kwargs):
        super().__init__(config, **kwargs)

        self.conf = config

        # Init dbs
        self.private_userdb = LookupMobileProofingUserDB(config.mongo_uri)
        self.proofing_log = ProofingLog(config.mongo_uri)

        # Init celery
        self.lookup_mobile_relay = LookupMobileRelay(config.celery)
        self.msg_relay = MsgRelay(config.celery)
        self.am_relay = AmRelay(config.celery, 'eduid_lookup_mobile_proofing')


current_mobilep_app = cast(MobileProofingApp, current_app)


def init_lookup_mobile_proofing_app(
    name: str = 'lookup_mobile_proofing', test_config: Optional[Mapping[str, Any]] = None
) -> MobileProofingApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    config = load_config(typ=MobileProofingConfig, app_name=name, ns='webapp', test_config=test_config)

    app = MobileProofingApp(config)

    app.logger.info(f'Init {app}...')

    # Register views
    from eduid_webapp.lookup_mobile_proofing.views import mobile_proofing_views

    app.register_blueprint(mobile_proofing_views)

    return app
