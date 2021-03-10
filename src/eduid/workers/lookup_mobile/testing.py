import logging

from eduid.common.config.base import CeleryConfigMixin, EduIDBaseAppConfig
from eduid.webapp.lookup_mobile_proofing.lookup_mobile_relay import LookupMobileRelay

from eduid.common.config.workers import MobConfig
from eduid.userdb.testing import MongoTestCase
from eduid.workers.lookup_mobile.common import MobWorkerSingleton

logger = logging.getLogger(__name__)


class MobTestConfig(EduIDBaseAppConfig, CeleryConfigMixin):
    pass


class LookupMobileMongoTestCase(MongoTestCase):
    def setUp(self, init_lookup_mobile=True, **kwargs):
        super().setUp(**kwargs)
        if init_lookup_mobile:
            settings = {
                'app_name': 'testing',
                'celery': {
                    'broker_transport': 'memory',
                    'broker_url': 'memory://',
                    'result_backend': 'cache',
                    'cache_backend': 'memory',
                },
                'devel_mode': True,
                'transaction_audit': False,
                'log_path': '',
                'teleadress_client_user': 'TEST',
                'teleadress_client_password': 'TEST',
                'mongo_uri': self.tmp_db.uri,
                'token_service_url': 'foo',
            }
            self.lookup_mobile_settings = MobConfig(**settings)

            MobWorkerSingleton.update_config(self.lookup_mobile_settings)
            logger.debug(f'Initialised lookup_mobile with config:\n{self.lookup_mobile_settings}')

            self.lookup_mobile_relay = LookupMobileRelay(MobTestConfig(**settings))
