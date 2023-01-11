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
from typing import Any, Optional, cast
from collections.abc import Mapping

from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.userdb.logs import ProofingLog
from eduid.userdb.proofing import OrcidProofingStateDB, OrcidProofingUserDB
from eduid.webapp.common.api import oidc
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.orcid.settings.common import OrcidConfig

__author__ = "lundberg"


class OrcidApp(AuthnBaseApp):
    def __init__(self, config: OrcidConfig, **kwargs):
        super().__init__(config, **kwargs)

        self.conf = config

        # Init dbs
        self.private_userdb = OrcidProofingUserDB(config.mongo_uri)
        self.proofing_statedb = OrcidProofingStateDB(config.mongo_uri)
        self.proofing_log = ProofingLog(config.mongo_uri)

        # Init celery
        self.am_relay = AmRelay(config)

        # Initialize the oidc_client
        self.oidc_client = oidc.init_client(config.client_registration_info, config.provider_configuration_info)


current_orcid_app: OrcidApp = cast(OrcidApp, current_app)


def init_orcid_app(name: str = "orcid", test_config: Optional[Mapping[str, Any]] = None) -> OrcidApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    config = load_config(typ=OrcidConfig, app_name=name, ns="webapp", test_config=test_config)

    app = OrcidApp(config)

    app.logger.info(f"Init {name} app...")

    # Register views
    from eduid.webapp.orcid.views import orcid_views

    app.register_blueprint(orcid_views)

    return app
