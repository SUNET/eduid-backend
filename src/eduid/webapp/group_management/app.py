from collections.abc import Mapping
from typing import Any, cast

from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.mail_relay import MailRelay
from eduid.userdb.group_management import GroupManagementInviteStateDB
from eduid.userdb.scimapi import ScimApiGroupDB
from eduid.userdb.scimapi.userdb import ScimApiUserDB
from eduid.webapp.common.api import translation
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.group_management.settings.common import GroupManagementConfig

__author__ = "lundberg"


class GroupManagementApp(AuthnBaseApp):
    def __init__(self, config: GroupManagementConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        self.conf = config

        # Init dbs
        self.invite_state_db = GroupManagementInviteStateDB(config.mongo_uri)
        _owner = config.scim_data_owner.replace(
            ".", "_"
        )  # dot is a name separator in mongodb, so replace dots with underscores
        self.scimapi_userdb = ScimApiUserDB(db_uri=config.mongo_uri, collection=f"{_owner}__users", setup_indexes=False)
        self.scimapi_groupdb = ScimApiGroupDB(
            neo4j_uri=config.neo4j_uri,
            neo4j_config=config.neo4j_config,
            scope=config.scim_data_owner,
            mongo_uri=config.mongo_uri,
            mongo_dbname="eduid_scimapi",
            mongo_collection=f"{_owner}__groups",
            setup_indexes=False,
        )

        # Init celery
        self.mail_relay = MailRelay(config)


current_group_management_app = cast(GroupManagementApp, current_app)


def init_group_management_app(
    name: str = "group_management", test_config: Mapping[str, Any] | None = None
) -> GroupManagementApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.

    :return: the flask app
    """
    config = load_config(typ=GroupManagementConfig, app_name=name, ns="webapp", test_config=test_config)

    app = GroupManagementApp(config)

    app.logger.info(f"Init {app}...")

    # Register views
    from eduid.webapp.group_management.views.group import group_management_views
    from eduid.webapp.group_management.views.invite import group_invite_views

    app.register_blueprint(group_management_views)
    app.register_blueprint(group_invite_views)

    # Init translation
    translation.init_babel(app)

    app.logger.info(f"{name!s} initialized")
    return app
