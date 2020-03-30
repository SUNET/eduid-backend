import logging
import logging.config
import sys
from typing import Dict, Optional

from neobolt.addressing import AddressError

from eduid_userdb import UserDB

from eduid_scimapi.config import ScimApiConfig
from eduid_scimapi.groupdb import ScimApiGroupDB
from eduid_scimapi.userdb import ScimApiUserDB
from eduid_scimapi.utils import urlappend


class Context(object):
    def __init__(self, config: ScimApiConfig):
        self.config = config

        # Setup logging
        if self.config.logging_config:
            logging.config.dictConfig(self.config.logging_config)
            self.logger = logging.getLogger('eduid_scimapi')
        else:
            self.logger = logging.getLogger('eduid_scimapi')
            sh = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(self.config.log_format)
            sh.setFormatter(formatter)
            self.logger.addHandler(sh)
            self.logger.setLevel(self.config.log_level)

        # Setup databases
        self.eduid_userdb = UserDB(db_uri=self.config.mongo_uri, db_name='eduid_am')
        self.userdb = ScimApiUserDB(db_uri=self.config.mongo_uri)
        if self.config.neo4j_uri:
            self.groupdb = ScimApiGroupDB(db_uri=self.config.neo4j_uri, config=self.config.neo4j_config)
        else:
            self.groupdb = None  # type: ignore
            # Temporarily don't care about neo4jdb
            self.logger.info(f'Starting without neo4jdb')

    @property
    def base_url(self) -> str:
        base_url = f'{self.config.schema}://{self.config.server_name}'
        if self.config.application_root:
            return urlappend(base_url, self.config.application_root)
        return base_url
