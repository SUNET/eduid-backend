import logging
import logging.config
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from eduid.common.config.base import DataOwnerConfig, DataOwnerName
from eduid.common.fastapi.context_request import ContextRequest
from eduid.common.fastapi.log import init_logging
from eduid.common.misc.timeutil import utc_now
from eduid.common.models.scim_base import SCIMResourceType
from eduid.common.utils import make_etag, urlappend
from eduid.queue.db.message import MessageDB
from eduid.scimapi.config import ScimApiConfig
from eduid.scimapi.notifications import NotificationRelay
from eduid.scimapi.utils import load_jwks
from eduid.userdb.scimapi import ScimApiEventDB, ScimApiGroup, ScimApiGroupDB
from eduid.userdb.scimapi.invitedb import ScimApiInvite, ScimApiInviteDB
from eduid.userdb.scimapi.userdb import ScimApiUser, ScimApiUserDB
from eduid.userdb.signup.invitedb import SignupInviteDB


@dataclass
class DataOwnerDatabases:
    data_owner: DataOwnerName
    userdb: ScimApiUserDB
    groupdb: ScimApiGroupDB
    invitedb: ScimApiInviteDB
    eventdb: ScimApiEventDB
    last_accessed: datetime = field(default_factory=utc_now)


class Context:
    def __init__(self, config: ScimApiConfig) -> None:
        self.name = config.app_name
        self.config = config

        # Setup logging
        init_logging(self.name, self.config)
        self.logger = logging.getLogger("eduid_scimapi")
        self.logger.info("Logging initialized")

        # Setup databases
        self._dbs: dict[DataOwnerName, DataOwnerDatabases] = {}
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

    @staticmethod
    def _get_db_name(data_owner: DataOwnerName, data_owner_config: DataOwnerConfig) -> str:
        if data_owner_config.db_name is not None:
            # If data_owner.db_name is set for this data owner use that instead of the default db_name
            return data_owner_config.db_name
        return data_owner.replace(".", "_")  # replace dots with underscores

    def _load_data_owner_dbs(self, data_owner: DataOwnerName) -> None:
        data_owner_config = self.config.data_owners.get(data_owner)
        if data_owner_config is None:
            raise ValueError(f"Data owner {data_owner} not found in config")
        db_name = self._get_db_name(data_owner=data_owner, data_owner_config=data_owner_config)
        self.logger.info(f"Loading databases for {data_owner} with db_name {db_name}")
        self._dbs[data_owner] = DataOwnerDatabases(
            data_owner=data_owner,
            userdb=ScimApiUserDB(db_uri=self.config.mongo_uri, collection=f"{db_name}__users"),
            groupdb=ScimApiGroupDB(
                neo4j_uri=self.config.neo4j_uri,
                neo4j_config=self.config.neo4j_config,
                scope=data_owner,
                mongo_uri=self.config.mongo_uri,
                mongo_dbname="eduid_scimapi",
                mongo_collection=f"{db_name}__groups",
            ),
            invitedb=ScimApiInviteDB(db_uri=self.config.mongo_uri, collection=f"{db_name}__invites"),
            eventdb=ScimApiEventDB(db_uri=self.config.mongo_uri, collection=f"{db_name}__events"),
        )

    def _get_data_owner_dbs(self, data_owner: DataOwnerName) -> DataOwnerDatabases:
        if data_owner not in self._dbs:
            self._load_data_owner_dbs(data_owner=data_owner)
        data_owner_dbs = self._dbs[data_owner]
        # update last accessed to help keep the cache from growing too large
        data_owner_dbs.last_accessed = utc_now()
        return data_owner_dbs

    def get_userdb(self, data_owner: DataOwnerName) -> ScimApiUserDB | None:
        return self._get_data_owner_dbs(data_owner=data_owner).userdb

    def get_groupdb(self, data_owner: DataOwnerName) -> ScimApiGroupDB | None:
        return self._get_data_owner_dbs(data_owner=data_owner).groupdb

    def get_invitedb(self, data_owner: DataOwnerName) -> ScimApiInviteDB | None:
        return self._get_data_owner_dbs(data_owner=data_owner).invitedb

    def get_eventdb(self, data_owner: DataOwnerName) -> ScimApiEventDB | None:
        return self._get_data_owner_dbs(data_owner=data_owner).eventdb

    def url_for(self, *args: Any) -> str:
        url = self.base_url
        for arg in args:
            url = urlappend(url, f"{arg}")
        return url

    def resource_url(self, resource_type: SCIMResourceType, scim_id: UUID) -> str:
        return self.url_for(resource_type.value + "s", str(scim_id))

    def check_version(self, req: ContextRequest, db_obj: ScimApiGroup | ScimApiUser | ScimApiInvite) -> bool:
        if req.headers.get("IF-MATCH") == make_etag(db_obj.version):
            return True
        self.logger.error("Version mismatch")
        self.logger.debug(f"{req.headers.get('IF-MATCH')} != {make_etag(db_obj.version)}")
        return False
