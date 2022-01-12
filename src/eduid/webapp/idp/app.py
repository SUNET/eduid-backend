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

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.userdb.actions import ActionDB
from eduid.userdb.actions.tou import ToUUserDB
from eduid.userdb.idp import IdPUserDb
from eduid.webapp.common.api import translation
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.authn.utils import init_pysaml2
from eduid.webapp.common.session import session
from eduid.webapp.idp import idp_authn
from eduid.webapp.idp.other_device import OtherDeviceDB
from eduid.webapp.idp.settings.common import IdPConfig
from eduid.webapp.idp.sso_cache import SSOSessionCache
from eduid.webapp.idp.sso_session import SSOSession, SSOSessionId

__author__ = 'ft'


class IdPApp(EduIDBaseApp):
    def __init__(self, config: IdPConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        self.conf = config

        # Init dbs
        # self.private_userdb = IdPUserDB(self.conf.mongo_uri)
        # Initiate external modules
        translation.init_babel(self)

        # Connecting to MongoDB can take some time if the replica set is not fully working.
        # Log both 'starting' and 'started' messages.
        self.logger.info("eduid-IdP server starting")

        self.logger.debug(f'Loading PySAML2 server using cfgfile {config.pysaml2_config}')
        self.IDP = init_pysaml2(config.pysaml2_config)

        if config.mongo_uri is None:
            raise RuntimeError('Mongo URI is not optional for the IdP')
        self.sso_sessions = SSOSessionCache(config.mongo_uri)

        self.authn_info_db = None

        self.actions_db = ActionDB(config.mongo_uri)

        self.userdb = IdPUserDb(db_uri=config.mongo_uri, db_name='eduid_am', collection='attributes')
        self.authn = idp_authn.IdPAuthn(config=config, userdb=self.userdb)
        self.tou_db = ToUUserDB(config.mongo_uri)
        self.other_device_db = OtherDeviceDB(config.mongo_uri)

        # Init celery
        self.am_relay = AmRelay(config)

        self.logger.info('eduid-IdP application started')

    def _lookup_sso_session(self) -> Optional[SSOSession]:
        """
        Locate any existing SSO session for this request.

        :returns: SSO session if found (and valid)
        """
        session = self._lookup_sso_session2()
        if session:
            self.logger.debug(f'SSO session found in the database: {session}')
            _age = session.age
            if _age > self.conf.sso_session_lifetime:
                self.logger.debug(f'SSO session expired (age {_age} > {self.conf.sso_session_lifetime})')
                return None
            self.logger.debug(f'SSO session is still valid (age {_age} <= {self.conf.sso_session_lifetime})')
        return session

    def _lookup_sso_session2(self) -> Optional[SSOSession]:
        """
        See if a SSO session exists for this request, and return the data about
        the currently logged in user from the session store.

        :return: Data about currently logged in user
        """
        _sso = None

        _session_id = self.get_sso_session_id()
        if _session_id:
            _sso = self.sso_sessions.get_session(_session_id)
            self.logger.debug(f'Looked up SSO session using session ID {repr(_session_id)}: {_sso}')

        if not _sso:
            self.logger.debug('SSO session not found using IdP SSO cookie')

            if session.idp.sso_cookie_val is not None:
                # Debug issues with browsers not returning updated SSO cookie values.
                # Only log partial cookie value since it allows impersonation if leaked.
                _other_session_id = SSOSessionId(session.idp.sso_cookie_val)
                self.logger.debug(
                    'Found potential sso_cookie_val in the eduID session: ' f'({session.idp.sso_cookie_val[:8]}...)'
                )
                _other_sso = self.sso_sessions.get_session(_other_session_id)
                if _other_sso is not None:
                    self.logger.info(
                        f'Found no SSO session, but found one from session.idp.sso_cookie_val: {_other_sso}'
                    )

            if session.common.eppn:
                for this in self.sso_sessions.get_sessions_for_user(session.common.eppn):
                    self.logger.info(
                        f'Found no SSO session, but found SSO session for user {session.common.eppn}: {this}'
                    )

            return None
        self.logger.debug(f'Loaded SSO session {_sso}')
        return _sso

    def get_sso_session_id(self) -> Optional[SSOSessionId]:
        """
        Get the SSO session id from the IdP SSO cookie.

        :return: SSO session id
        """
        # local import to avoid import-loop
        from eduid.webapp.idp.mischttp import read_cookie

        _session_id = read_cookie(self.conf.sso_cookie.key)
        if not _session_id:
            return None
        self.logger.debug(f'Got SSO session ID from IdP SSO cookie {repr(_session_id)}')
        return SSOSessionId(_session_id)


current_idp_app = cast(IdPApp, current_app)


def init_idp_app(name: str = 'idp', test_config: Optional[Mapping[str, Any]] = None) -> IdPApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override configuration - used in tests.

    :return: the flask app
    """
    config = load_config(typ=IdPConfig, app_name=name, ns='webapp', test_config=test_config)

    app = IdPApp(config, handle_exceptions=False)

    # Register views
    from eduid.webapp.idp.views import idp_views
    from eduid.webapp.idp.views2.other_device import other_device_views

    app.register_blueprint(idp_views)
    app.register_blueprint(other_device_views)

    from eduid.webapp.idp.exceptions import init_exception_handlers

    app = init_exception_handlers(app)

    app.logger.info(f'{name} initialized')
    return app
