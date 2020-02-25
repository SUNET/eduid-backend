import logging
import logging.config
import sys
from typing import Dict

from eduid_scimapi.config import load_config
from eduid_scimapi.utils import urlappend
from eduid_userdb import UserDB


class Context(object):

    def __init__(self, config: Dict, testing: bool=False):
        self.config = load_config(config, testing=testing)
        self.users: UserStore = UserStore()

        self.userdb = UserDB(db_uri=self.config.mongo_uri, db_name='eduid_am')

        if self.config.get('LOGGING'):
            logging.config.dictConfig(self.config.get('LOGGING', {}))
            self.logger = logging.getLogger('eduid_scimapi')
        else:
            self.logger = logging.getLogger('eduid_scimapi')
            sh = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(module)s - %(levelname)s - %(message)s')
            sh.setFormatter(formatter)
            self.logger.addHandler(sh)
            self.logger.setLevel(logging.DEBUG)

    @property
    def base_url(self) -> str:
        base_url = f'{self.config.schema}://{self.config.server_name}'
        if self.config.application_root:
            return urlappend(base_url, self.config.application_root)
        return base_url
