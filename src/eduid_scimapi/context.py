import logging
import logging.config
import sys
from typing import Optional

from eduid_scimapi.config import ScimApiConfig
from eduid_scimapi.groupdb import ScimApiGroupDB
from eduid_scimapi.userdb import ScimApiUserDB
from eduid_scimapi.utils import urlappend


class Context(object):
    def __init__(self, name: str, config: ScimApiConfig):
        self.name = name
        self.config = config

        # Setup logging
        if self.config.logging_config:
            logging.config.dictConfig(self.config.logging_config)
            self.logger = logging.getLogger('eduid_scimapi')
        else:
            self.logger = logging.getLogger('eduid_scimapi')
            self.logger.handlers = []  # Unset any other handlers
            sh = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(self.config.log_format)
            sh.setFormatter(formatter)
            self.logger.addHandler(sh)
            self.logger.setLevel(self.config.log_level)

        # Setup databases
        self._userdbs = {}
        self._groupdbs = {}
        for data_owner in self.config.data_owners:
            _owner = data_owner.replace('.', '_')  # replace dots with underscores
            self._userdbs[data_owner] = ScimApiUserDB(db_uri=self.config.mongo_uri, collection=f'{_owner}__users')
            self._groupdbs[data_owner] = ScimApiGroupDB(
                neo4j_uri=self.config.neo4j_uri,
                neo4j_config=self.config.neo4j_config,
                scope=data_owner,
                mongo_uri=self.config.mongo_uri,
                mongo_dbname='eduid_scimapi',
                mongo_collection=f'{_owner}__groups',
            )

    @property
    def base_url(self) -> str:
        base_url = f'{self.config.schema}://{self.config.server_name}'
        if self.config.application_root:
            return urlappend(base_url, self.config.application_root)
        return base_url

    def get_userdb(self, data_owner: str) -> Optional[ScimApiUserDB]:
        return self._userdbs.get(data_owner)

    def get_groupdb(self, data_owner: str) -> Optional[ScimApiGroupDB]:
        return self._groupdbs.get(data_owner)
