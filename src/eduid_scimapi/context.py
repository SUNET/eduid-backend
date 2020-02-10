import logging
import logging.config
import sys
from typing import Mapping

from eduid_scimapi.utils import urlappend
from eduid_scimapi.user import UserStore


class Context(object):

    def __init__(self, config: Mapping):
        self.config = config
        self.users: UserStore = UserStore()

        self.schema: str = self.config.get('SCHEMA', 'http')
        self.server_name: str = self.config.get('SERVER_NAME', 'localhost:8000')
        self.application_root: str = self.config.get('APPLICATION_ROOT', '')


        if self.config.get('LOGGING'):
            logging.config.dictConfig(self.config.get('LOGGING'))
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
        base_url = f'{self.schema}://{self.server_name}'
        if self.application_root:
            return urlappend(base_url, self.application_root)
        return base_url
