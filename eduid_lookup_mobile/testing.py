from __future__ import absolute_import

from eduid_userdb.testing import MongoTestCase


class LookupMobileMongoTestCase(MongoTestCase):
    def setUp(self, init_lookup_mobile=True):
        super(LookupMobileMongoTestCase, self).setUp()
        if init_lookup_mobile:
            self.lookup_mobile_settings = {
                'CELERY': {'broker_transport': 'memory',
                           'broker_url': 'memory://',
                           'result_backend': 'cache',
                           'cache_backend': 'memory',
                           },
                'DEVEL_MODE': True,
                'TRANSACTION_AUDIT': False,
                'LOG_PATH': '',
                'TELEADRESS_CLIENT_USER': 'TEST',
                'TELEADRESS_CLIENT_PASSWORD': 'TEST',
            }
            # initialize eduid_lookup_mobile without requiring config in etcd
            from eduid_lookup_mobile import init_app
            self.lookup_mobile = init_app(self.lookup_mobile_settings['CELERY'])
            import eduid_lookup_mobile.worker
            eduid_lookup_mobile.worker.worker_config = self.lookup_mobile_settings
