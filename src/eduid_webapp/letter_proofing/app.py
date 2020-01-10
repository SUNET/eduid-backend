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
from flask import current_app

from eduid_common.api import am, msg
from eduid_common.api.app import get_app_config
from eduid_common.authn.middleware import AuthnBaseApp
from eduid_userdb.logs import ProofingLog
from eduid_userdb.proofing import LetterProofingStateDB, LetterProofingUserDB
from eduid_webapp.letter_proofing.ekopost import Ekopost
from eduid_webapp.letter_proofing.settings.common import LetterProofingConfig

__author__ = 'lundberg'


class LetterProofingApp(AuthnBaseApp):

    def __init__(self, name: str, config: dict, **kwargs):

        super(LetterProofingApp, self).__init__(name, LetterProofingConfig,
                                                config, **kwargs)

        # Register views
        from eduid_webapp.letter_proofing.views import letter_proofing_views
        self.register_blueprint(letter_proofing_views)

        # Init dbs
        self.private_userdb = LetterProofingUserDB(self.config.mongo_uri)
        self.proofing_statedb = LetterProofingStateDB(self.config.mongo_uri)
        self.proofing_log = ProofingLog(self.config.mongo_uri)
        # Init celery
        msg.init_relay(self)
        am.init_relay(self, 'eduid_letter_proofing')
        # Initiate external modules
        self.ekopost = Ekopost(self)


def get_current_app() -> LetterProofingApp:
    """Teach pycharm about app"""
    return current_app  # type: ignore


current_letterp_app = get_current_app()


def init_letter_proofing_app(name: str, config: dict) -> LetterProofingApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases
    """
    app = LetterProofingApp(name, config)

    app.logger.info(f'Init {name} app...')

    return app
