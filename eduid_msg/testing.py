from __future__ import absolute_import

import pkg_resources

from eduid_userdb.testing import MongoTestCase


class MsgMongoTestCase(MongoTestCase):
    def setUp(self, init_msg=True):
        super(MsgMongoTestCase, self).setUp()
        data_dir = pkg_resources.resource_filename(__name__, 'tests/data')
        if init_msg:
            self.msg_settings = {
                'broker_transport': 'memory',
                'broker_url': 'memory://',
                'task_eager_propagates': True,
                'task_always_eager': True,
                'result_backend': 'cache',
                'cache_backend': 'memory',
                'MONGO_URI': self.tmp_db.uri,
                'MONGO_DBNAME': 'test',
                'SMS_ACC': 'foo',
                'SMS_KEY': 'bar',
                'SMS_SENDER': 'Test sender',
                'TEMPLATE_DIR': data_dir,
                'MESSAGE_RATE_LIMIT': '2/m',
            }
            import eduid_msg
            self.msg = eduid_msg.init_app(self.msg_settings)
