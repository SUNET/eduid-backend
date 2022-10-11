import logging
import logging.config
from typing import Optional, Union
from uuid import UUID

from eduid.common.utils import urlappend
from eduid.queue.db.message import MessageDB
from eduid.scimapi.config import DataOwnerName, ScimApiConfig
from eduid.scimapi.context_request import ContextRequest
from eduid.scimapi.log import init_logging
from eduid.common.models.scim_base import SCIMResourceType
from eduid.scimapi.notifications import NotificationRelay
from eduid.scimapi.utils import load_jwks, make_etag
from eduid.userdb.scimapi import ScimApiEventDB, ScimApiGroup, ScimApiGroupDB
from eduid.userdb.scimapi.invitedb import ScimApiInvite, ScimApiInviteDB
from eduid.userdb.scimapi.userdb import ScimApiUser, ScimApiUserDB
from eduid.userdb.signup.invitedb import SignupInviteDB


class Context(object):
    def __init__(self, config: ScimApiConfig):
        self.name = config.app_name
        self.config = config

        # Setup logging
        init_logging(self.name, self.config)
        self.logger = logging.getLogger("eduid_scimapi")
        self.logger.info("Logging initialized")

        # Setup databases
        self._userdbs = {}
        self._groupdbs = {}
        self._invitedbs = {}
        self._eventdbs = {}
        for data_owner_id, data_owner in self.config.data_owners.items():
            db_name = data_owner_id.replace(".", "_")  # replace dots with underscores
            if data_owner.db_name is not None:
                # If data_owner.db_name is set for this data owner use that instead of the default db_name
                db_name = data_owner.db_name

            self._userdbs[data_owner_id] = ScimApiUserDB(db_uri=self.config.mongo_uri, collection=f"{db_name}__users")
            self._groupdbs[data_owner_id] = ScimApiGroupDB(
                neo4j_uri=self.config.neo4j_uri,
                neo4j_config=self.config.neo4j_config,
                scope=data_owner_id,
                mongo_uri=self.config.mongo_uri,
                mongo_dbname="eduid_scimapi",
                mongo_collection=f"{db_name}__groups",
            )
            self._invitedbs[data_owner_id] = ScimApiInviteDB(
                db_uri=self.config.mongo_uri, collection=f"{db_name}__invites"
            )
            self._eventdbs[data_owner_id] = ScimApiEventDB(
                db_uri=self.config.mongo_uri, collection=f"{db_name}__events"
            )
        self.signup_invitedb = SignupInviteDB(db_uri=self.config.mongo_uri)
        self.messagedb = MessageDB(db_uri=self.config.mongo_uri)

        # Setup notifications
        self.notification_relay = NotificationRelay(self.config)

        # Setup keystore
        self.jwks = load_jwks(config)

    @property
    def base_url(self) -> str:
        base_url = f"{self.config.protocol}://{self.config.server_name}"
        if self.config.application_root:
            return urlappend(base_url, self.config.application_root)
        return base_url

    def get_userdb(self, data_owner: DataOwnerName) -> Optional[ScimApiUserDB]:
        return self._userdbs.get(data_owner)

    def get_groupdb(self, data_owner: DataOwnerName) -> Optional[ScimApiGroupDB]:
        return self._groupdbs.get(data_owner)

    def get_invitedb(self, data_owner: DataOwnerName) -> Optional[ScimApiInviteDB]:
        return self._invitedbs.get(data_owner)

    def get_eventdb(self, data_owner: DataOwnerName) -> Optional[ScimApiEventDB]:
        return self._eventdbs.get(data_owner)

    def url_for(self, *args) -> str:
        url = self.base_url
        for arg in args:
            url = urlappend(url, f"{arg}")
        return url

    def resource_url(self, resource_type: SCIMResourceType, scim_id: UUID) -> str:
        return self.url_for(resource_type.value + "s", str(scim_id))

    def check_version(self, req: ContextRequest, db_obj: Union[ScimApiGroup, ScimApiUser, ScimApiInvite]) -> bool:
        if req.headers.get("IF-MATCH") == make_etag(db_obj.version):
            return True
        self.logger.error(f"Version mismatch")
        self.logger.debug(f'{req.headers.get("IF-MATCH")} != {make_etag(db_obj.version)}')
        return False
