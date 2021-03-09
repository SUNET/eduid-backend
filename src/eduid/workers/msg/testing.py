import pkg_resources

from eduid.common.config.workers import MsgConfig
from eduid.userdb.testing import MongoTestCase


class MsgMongoTestCase(MongoTestCase):
    def setUp(self, init_msg=True):
        super(MsgMongoTestCase, self).setUp()
        data_dir = pkg_resources.resource_filename(__name__, 'tests/data')
        if init_msg:
            settings = {
                'app_name': 'testing',
                'celery': {
                    'broker_transport': 'memory',
                    'broker_url': 'memory://',
                    'task_eager_propagates': True,
                    'task_always_eager': True,
                    'result_backend': 'cache',
                    'cache_backend': 'memory',
                },
                'mongo_uri': self.tmp_db.uri,
                'mongo_dbname': 'test',
                'sms_acc': 'foo',
                'sms_key': 'bar',
                'sms_sender': 'Test sender',
                'template_dir': data_dir,
                'message_rate_limit': 2,
            }
            self.msg_settings = MsgConfig(**settings)
            # initialize eduid.workers.msg without requiring config in etcd
            import eduid.workers.msg

            self.msg = eduid.workers.msg.init_app(self.msg_settings.celery)
            import eduid.workers.msg.worker

            eduid.workers.msg.worker.worker_config = self.msg_settings
