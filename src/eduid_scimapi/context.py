import logging
import logging.config
from typing import Optional

from eduid_queue.db.message import MessageDB

from eduid_userdb.signup.invitedb import SignupInviteDB

from eduid_scimapi.config import ScimApiConfig
from eduid_scimapi.db.eventdb import ScimApiEventDB
from eduid_scimapi.db.groupdb import ScimApiGroupDB
from eduid_scimapi.db.invitedb import ScimApiInviteDB
from eduid_scimapi.db.userdb import ScimApiUserDB
from eduid_scimapi.log import init_logging
from eduid_scimapi.utils import urlappend


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
        self._eventdbs = {}
        self._groupdbs = {}
        self._invitedbs = {}
        for data_owner in self.config.data_owners:
            _owner = data_owner.replace('.', '_')  # replace dots with underscores
            _eventdb = ScimApiEventDB(db_uri=self.config.mongo_uri, collection=f'{_owner}__events')
            self._eventdbs[data_owner] = _eventdb
            self._userdbs[data_owner] = ScimApiUserDB(
                db_uri=self.config.mongo_uri, eventdb=_eventdb, collection=f'{_owner}__users'
            )
            self._groupdbs[data_owner] = ScimApiGroupDB(
                neo4j_uri=self.config.neo4j_uri,
                neo4j_config=self.config.neo4j_config,
                scope=data_owner,
                mongo_uri=self.config.mongo_uri,
                mongo_dbname='eduid_scimapi',
                mongo_collection=f'{_owner}__groups',
            )
            self._invitedbs[data_owner] = ScimApiInviteDB(db_uri=self.config.mongo_uri, collection=f'{_owner}__invites')
        self.signup_invitedb = SignupInviteDB(db_uri=self.config.mongo_uri)
        self.messagedb = MessageDB(db_uri=self.config.mongo_uri)

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
