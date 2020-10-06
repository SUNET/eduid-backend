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
import logging
import pprint
import threading
from typing import Any, Dict, Optional, cast

from flask import current_app

from eduid_common.api import am, msg, translation
from eduid_common.api.app import EduIDBaseApp
from eduid_common.authn.utils import init_pysaml2
from eduid_common.session.sso_cache import SSOSessionCache
from eduid_webapp.idp import mischttp
from eduid_webapp.idp.context import IdPContext

from eduid_webapp.idp.settings.common import IdPConfig

from eduid_common.authn import idp_authn
from eduid_common.authn.utils import init_pysaml2
from eduid_common.session import sso_cache, sso_session
from eduid_common.session.sso_cache import SSOSessionCache
from eduid_common.session.sso_session import SSOSession
from eduid_userdb.actions import ActionDB
from eduid_userdb.idp import IdPUserDb

#import eduid_idp.mischttp
#from eduid_idp.context import IdPContext
#from eduid_idp.login import SSO
#from eduid_idp.logout import SLO
#from eduid_idp.shared_session import EduidSession

logger = logging.getLogger(__name__)


__author__ = 'ft'


class IdPApp(EduIDBaseApp):

    def __init__(self, name: str, config: Dict, userdb: Optional[Any] = None, **kwargs):
        # Initialise type of self.config before any parent class sets a precedent to mypy
        self.config = IdPConfig.init_config(ns='webapp', app_name=name, test_config=config)
        super().__init__(name, **kwargs)
        # cast self.config because sometimes mypy thinks it is a FlaskConfig after super().__init__()
        self.config: IdPConfig = cast(IdPConfig, self.config)
        # Init dbs
        #self.private_userdb = IdPUserDB(self.config.mongo_uri)
        # Initiate external modules
        translation.init_babel(self)

        # Connecting to MongoDB can take some time if the replica set is not fully working.
        # Log both 'starting' and 'started' messages.
        self.logger.info("eduid-IdP server starting")

        logger.debug(f"Loading PySAML2 server using cfgfile {self.config.pysaml2_config}")
        self.IDP = init_pysaml2(self.config.pysaml2_config)

        _session_ttl = self.config.sso_session_lifetime * 60
        _SSOSessions: SSOSessionCache
        if self.config.sso_session_mongo_uri:
            _SSOSessions = sso_cache.SSOSessionCacheMDB(self.config.sso_session_mongo_uri, self.logger, _session_ttl)
        else:
            _SSOSessions = sso_cache.SSOSessionCacheMem(self.logger, _session_ttl, threading.Lock())

        _login_state_ttl = (self.config.login_state_ttl + 1) * 60
        self.authn_info_db = None
        _actions_db = None

        if self.config.mongo_uri:
            self.authn_info_db = idp_authn.AuthnInfoStoreMDB(self.config.mongo_uri, logger)

        if self.config.mongo_uri and self.config.actions_app_uri:
            _actions_db = ActionDB(self.config.mongo_uri)
            self.logger.info("configured to redirect users with pending actions")
        else:
            self.logger.debug("NOT configured to redirect users with pending actions")

        if userdb is None:
            # This is used in tests at least
            userdb = IdPUserDb(logger, self.config.mongo_uri, db_name=self.config.userdb_mongo_database)
        self.userdb = userdb
        self.authn = idp_authn.IdPAuthn(logger, self.config, self.userdb)

        self.logger.info('eduid-IdP application started')

        self.context = IdPContext(
            config=self.config,
            idp=self.IDP,
            logger=self.logger,
            sso_sessions=_SSOSessions,
            actions_db=_actions_db,
            authn=self.authn,
        )


    def _lookup_sso_session(self):
        """
        Locate any existing SSO session for this request.

        :returns: SSO session if found (and valid)
        :rtype: SSOSession | None
        """
        session = self._lookup_sso_session2()
        if session:
            self.logger.debug("SSO session for user {!r} found in IdP cache".format(session.user_id))
            session.set_user(self.userdb.lookup_user(session.user_id))
            if not session.idp_user:
                return None
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
        _session_id = mischttp.get_idpauthn_cookie(self.logger)
        if _session_id:
            _data = self.context.sso_sessions.get_session(sso_cache.SSOSessionId(_session_id))
            self.logger.debug("Looked up SSO session using idpauthn cookie :\n{!s}".format(_data))
        else:
            query = mischttp.parse_query_string(self.logger)
            if query:
                if 'id' in query:
                    self.logger.warning('Found "id" in query string - this was thought to be obsolete')
                self.logger.debug("Parsed query string :\n{!s}".format(pprint.pformat(query)))
                try:
                    _data = self.context.sso_sessions.get_session(query['id'])
                    self.logger.debug(
                        "Looked up SSO session using query 'id' parameter :\n{!s}".format(pprint.pformat(_data))
                    )
                except KeyError:
                    # no 'id', or not found in cache
                    pass
        if not _data:
            self.logger.debug("SSO session not found using 'id' parameter or 'idpauthn' cookie")
            return None
        _sso = sso_session.from_dict(_data)
        self.logger.debug("Re-created SSO session {!r}".format(_sso))
        return _sso


current_idp_app = cast(IdPApp, current_app)


def init_idp_app(name: str, config: Dict) -> IdPApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases

    :return: the flask app
    """
    app = IdPApp(name, config)

    # Register views
    from eduid_webapp.idp.views import idp_views
    app.register_blueprint(idp_views)

    app.logger.info(f'{name} initialized')
    return app
