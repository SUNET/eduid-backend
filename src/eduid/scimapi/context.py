import logging
import logging.config
from typing import Optional

from eduid.queue.db.message import MessageDB
from eduid.scimapi.config import ScimApiConfig
from eduid.scimapi.db.eventdb import ScimApiEventDB
from eduid.scimapi.db.groupdb import ScimApiGroupDB
from eduid.scimapi.db.invitedb import ScimApiInviteDB
from eduid.scimapi.db.userdb import ScimApiUserDB
from eduid.scimapi.log import init_logging
from eduid.scimapi.notifications import NotificationRelay
from eduid.scimapi.utils import urlappend
from eduid.userdb.signup.invitedb import SignupInviteDB


class Context(object):
    def __init__(self, config: ScimApiConfig):
        self.name = config.app_name
        self.config = config

        # Setup logging
        init_logging(self.name, self.config)
        self.logger = logging.getLogger('eduid_scimapi')
        self.logger.info('Logging initialized')

        # Setup databases
        self._userdbs = {}
        self._groupdbs = {}
        self._invitedbs = {}
        self._eventdbs = {}
        for data_owner_id, data_owner in self.config.data_owners.items():
            db_name = data_owner_id.replace('.', '_')  # replace dots with underscores
            if data_owner.db_name is not None:
                # If data_owner.db_name is set for this data owner use that instead of the default db_name
                db_name = data_owner.db_name

            self._userdbs[data_owner_id] = ScimApiUserDB(db_uri=self.config.mongo_uri, collection=f'{db_name}__users')
            self._groupdbs[data_owner_id] = ScimApiGroupDB(
                neo4j_uri=self.config.neo4j_uri,
                neo4j_config=self.config.neo4j_config,
                scope=data_owner_id,
                mongo_uri=self.config.mongo_uri,
                mongo_dbname='eduid_scimapi',
                mongo_collection=f'{db_name}__groups',
            )
            self._invitedbs[data_owner_id] = ScimApiInviteDB(
                db_uri=self.config.mongo_uri, collection=f'{db_name}__invites'
            )
            self._eventdbs[data_owner_id] = ScimApiEventDB(
                db_uri=self.config.mongo_uri, collection=f'{db_name}__events'
            )
        self.signup_invitedb = SignupInviteDB(db_uri=self.config.mongo_uri)
        self.messagedb = MessageDB(db_uri=self.config.mongo_uri)

        # Setup notifications
        self.notification_relay = NotificationRelay(self.config)

    @property
    def base_url(self) -> str:
        base_url = f'{self.config.protocol}://{self.config.server_name}'
        if self.config.application_root:
            return urlappend(base_url, self.config.application_root)
        return base_url

    def get_userdb(self, data_owner: str) -> Optional[ScimApiUserDB]:
        return self._userdbs.get(data_owner)

    def get_groupdb(self, data_owner: str) -> Optional[ScimApiGroupDB]:
        return self._groupdbs.get(data_owner)

    def get_invitedb(self, data_owner: str) -> Optional[ScimApiInviteDB]:
        return self._invitedbs.get(data_owner)

    def get_eventdb(self, data_owner: str) -> Optional[ScimApiEventDB]:
        return self._eventdbs.get(data_owner)
