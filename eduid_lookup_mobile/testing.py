from __future__ import absolute_import

from eduid_common.config.workers import MobConfig
from eduid_userdb.testing import MongoTestCase


class LookupMobileMongoTestCase(MongoTestCase):
    def setUp(self, init_lookup_mobile=True):
        super().setUp()
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
            }
            self.lookup_mobile_settings = MobConfig(**settings)
            # initialize eduid_lookup_mobile without requiring config in etcd
            from eduid_lookup_mobile import init_app

            self.lookup_mobile = init_app(self.lookup_mobile_settings.celery)
            import eduid_lookup_mobile.worker

            eduid_lookup_mobile.worker.worker_config = self.lookup_mobile_settings
