from __future__ import absolute_import

from eduid_userdb.testing import MongoTestCase


class LookupMobileMongoTestCase(MongoTestCase):
    def setUp(self, init_lookup_mobile=True):
        super(LookupMobileMongoTestCase, self).setUp()
        if init_lookup_mobile:
            self.lookup_mobile_settings = {
                'broker_transport': 'memory',
                'broker_url': 'memory://',
                'DEVEL_MODE': True,
                'TRANSACTION_AUDIT': False,
                'LOG_PATH': '',
                'TELEADRESS_CLIENT_USER': 'TEST',
                'TELEADRESS_CLIENT_PASSWORD': 'TEST',
            }
            import eduid_lookup_mobile
            self.msg = eduid_lookup_mobile.init_app(self.lookup_mobile_settings)
