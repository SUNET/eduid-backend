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

import pprint
from base64 import b64decode
from typing import Any, Dict, Optional, cast

from flask import current_app

from eduid_common.api import translation
from eduid_common.api.app import EduIDBaseApp
from eduid_common.authn import idp_authn
from eduid_common.authn.utils import init_pysaml2
from eduid_common.session import sso_cache, sso_session
from eduid_common.session.sso_session import SSOSession
from eduid_userdb.actions import ActionDB
from eduid_userdb.idp import IdPUserDb

from eduid_webapp.idp.settings.common import IdPConfig

__author__ = 'ft'


class IdPApp(EduIDBaseApp):
    def __init__(self, name: str, config: Dict, userdb: Optional[Any] = None, **kwargs):
        # Initialise type of self.config before any parent class sets a precedent to mypy
        self.config = IdPConfig.init_config(ns='webapp', app_name=name, test_config=config)
        super().__init__(name, **kwargs)
        # cast self.config because sometimes mypy thinks it is a FlaskConfig after super().__init__()
        self.config: IdPConfig = cast(IdPConfig, self.config)  # type: ignore
        # Init dbs
        # self.private_userdb = IdPUserDB(self.config.mongo_uri)
        # Initiate external modules
        translation.init_babel(self)

        # Connecting to MongoDB can take some time if the replica set is not fully working.
        # Log both 'starting' and 'started' messages.
        self.logger.info("eduid-IdP server starting")

        self.logger.debug(f"Loading PySAML2 server using cfgfile {self.config.pysaml2_config}")
        self.IDP = init_pysaml2(self.config.pysaml2_config)

        if self.config.sso_session_mongo_uri:
            self.logger.info('Config parameter sso_session_mongo_uri ignored. Used mongo_uri instead.')

        _session_ttl = self.config.sso_session_lifetime * 60
        self.sso_sessions = sso_cache.SSOSessionCacheMDB(self.config.mongo_uri, None, _session_ttl)

        _login_state_ttl = (self.config.login_state_ttl + 1) * 60
        self.authn_info_db = None
        self.actions_db = None

        if self.config.mongo_uri:
            self.authn_info_db = idp_authn.AuthnInfoStoreMDB(self.config.mongo_uri, logger=None)

        if self.config.mongo_uri and self.config.actions_app_uri:
            self.actions_db = ActionDB(self.config.mongo_uri)
            self.logger.info("configured to redirect users with pending actions")
        else:
            self.logger.debug("NOT configured to redirect users with pending actions")

        if userdb is None:
            # This is used in tests at least
            userdb = IdPUserDb(logger=None, mongo_uri=self.config.mongo_uri, db_name=self.config.userdb_mongo_database)
        self.userdb = userdb
        self.authn = idp_authn.IdPAuthn(logger=None, config=self.config, userdb=self.userdb)
        self.logger.info('eduid-IdP application started')

    def _lookup_sso_session(self) -> Optional[SSOSession]:
        """
        Locate any existing SSO session for this request.

        :returns: SSO session if found (and valid)
        """
        session = self._lookup_sso_session2()
        if session:
            session.set_user(self.userdb.lookup_user(session.user_id))
            if not session.idp_user:
                self.logger.debug(f'No IdPUser found for user_id {session.user_id} - ignoring session')
                return None
            self.logger.debug(f'SSO session for user {session.idp_user} found in IdP cache: {session}')
            _age = session.minutes_old
            if _age > self.config.sso_session_lifetime:
                self.logger.debug(
                    "SSO session expired (age {!r} minutes > {!r})".format(_age, self.config.sso_session_lifetime)
                )
                return None
            self.logger.debug(
                "SSO session is still valid (age {!r} minutes <= {!r})".format(_age, self.config.sso_session_lifetime)
            )
        return session

    def _lookup_sso_session2(self) -> Optional[SSOSession]:
        """
        See if a SSO session exists for this request, and return the data about
        the currently logged in user from the session store.

        :return: Data about currently logged in user
        """
        _data = None

        _session_id = self.get_sso_session_id()
        if _session_id:
            _data = self.sso_sessions.get_session(_session_id)
            self.logger.debug(f'Looked up SSO session using session ID {repr(_session_id)}:\n{_data}')

        if not _data:
            self.logger.debug("SSO session not found using 'id' parameter or 'idpauthn' cookie")
            return None
        _sso = sso_session.from_dict(_data)
        self.logger.debug("Re-created SSO session {!r}".format(_sso))
        return _sso

    def get_sso_session_id(self) -> Optional[sso_cache.SSOSessionId]:
        """
        Get the SSO session id from the idpauthn cookie, with fallback to hopefully unused 'id' query string parameter.

        :return: SSO session id
        """
        # local import to avoid import-loop
        from eduid_webapp.idp.mischttp import parse_query_string, read_cookie

        _session_id = read_cookie('idpauthn')
        if _session_id:
            # The old IdP base64 encoded the session_id, try to  remain interoperable. Fingers crossed.
            _decoded_session_id = b64decode(_session_id)
            self.logger.debug(f'Got SSO session ID from idpauthn cookie {_session_id} -> {_decoded_session_id}')
            return sso_cache.SSOSessionId(_decoded_session_id)

        query = parse_query_string()
        if query and 'id' in query:
            self.logger.warning('Found "id" in query string - this was thought to be obsolete')
            self.logger.debug("Parsed query string :\n{!s}".format(pprint.pformat(query)))
            _session_id = query['id']
            self.logger.debug(f'Got SSO session ID from query string: {_session_id}')
            return sso_cache.SSOSessionId(_session_id)

        return None


current_idp_app = cast(IdPApp, current_app)


def init_idp_app(name: str, config: Dict) -> IdPApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases

    :return: the flask app
    """
    app = IdPApp(name, config, handle_exceptions=False)

    # Register views
    from eduid_webapp.idp.views import idp_views

    app.register_blueprint(idp_views)

    from eduid_webapp.idp.exceptions import init_exception_handlers

    app = init_exception_handlers(app)

    app.logger.info(f'{name} initialized')
    return app
