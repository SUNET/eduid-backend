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

from typing import Dict, cast

from flask import current_app

from eduid_common.api import mail_relay, translation
from eduid_common.authn.middleware import AuthnBaseApp
from eduid_common.config.exceptions import BadConfiguration
from eduid_scimapi.groupdb import ScimApiGroupDB
from eduid_scimapi.userdb import ScimApiUserDB
from eduid_userdb.group_management import GroupManagementInviteStateDB

from eduid_webapp.group_management.settings.common import GroupManagementConfig

__author__ = 'lundberg'


class GroupManagementApp(AuthnBaseApp):
    def __init__(self, name: str, config: dict, **kwargs):
        # Initialise type of self.config before any parent class sets a precedent to mypy
        self.config = GroupManagementConfig.init_config(ns='webapp', app_name=name, test_config=config)
        super().__init__(name, **kwargs)
        # cast self.config because sometimes mypy thinks it is a FlaskConfig after super().__init__()
        self.config: GroupManagementConfig = cast(GroupManagementConfig, self.config)  # type: ignore

        # Init dbs
        if self.config.mongo_uri is None:
            raise BadConfiguration('mongo_uri not set')
        self.invite_state_db = GroupManagementInviteStateDB(self.config.mongo_uri)
        _owner = self.config.scim_data_owner.replace(
            '.', '_'
        )  # dot is a name separator in mongodb, so replace dots with underscores
        self.scimapi_userdb = ScimApiUserDB(db_uri=self.config.mongo_uri, collection=f'{_owner}__users')
        self.scimapi_groupdb = ScimApiGroupDB(
            neo4j_uri=self.config.neo4j_uri,
            neo4j_config=self.config.neo4j_config,
            scope=self.config.scim_data_owner,
            mongo_uri=self.config.mongo_uri,
            mongo_dbname='eduid_scimapi',
            mongo_collection=f'{_owner}__groups',
        )
        # Init celery
        mail_relay.init_relay(self)

        # Init translation
        translation.init_babel(self)


current_group_management_app = cast(GroupManagementApp, current_app)


def init_group_management_app(name: str, config: Dict) -> GroupManagementApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases

    :return: the flask app
    """
    app = GroupManagementApp(name, config)

    # Register views
    from eduid_webapp.group_management.views.group import group_management_views
    from eduid_webapp.group_management.views.invite import group_invite_views

    app.register_blueprint(group_management_views)
    app.register_blueprint(group_invite_views)

    app.logger.info('{!s} initialized'.format(name))
    return app
