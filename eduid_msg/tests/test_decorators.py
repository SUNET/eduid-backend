from eduid_msg.tests import MongoTestCase
from eduid_msg.celery import celery
from eduid_msg.decorators import TransactionAudit
import pkg_resources


class TestTransactionAudit(MongoTestCase):
    def setUp(self):
        super(TestTransactionAudit, self).setUp()
        TransactionAudit.enable()
        data_dir = pkg_resources.resource_filename(__name__, 'data')
        settings = {
            'BROKER_TRANSPORT': 'memory',
            'BROKER_URL': 'memory://',
            'CELERY_EAGER_PROPAGATES_EXCEPTIONS': True,
            'CELERY_ALWAYS_EAGER': True,
            'CELERY_RESULT_BACKEND': "cache",
            'CELERY_CACHE_BACKEND': 'memory',
            'MONGO_URI': 'mongodb://localhost:%d/' % self.port,
            'MONGO_DBNAME': 'test',
            'SMS_ACC': 'foo',
            'SMS_KEY': 'bar',
            'SMS_SENDER': 'Test sender',
            'MM_DEFAULT_SUBJECT': 'Test case',
            'MM_SENDER_ORG_NR': '1234567',
            'TEMPLATE_DIR': data_dir,
            'MESSAGE_RATE_LIMIT': '2/m',
        }
        celery.conf.update(settings)

    def test_transaction_audit(self):
        @TransactionAudit(celery.conf.get('MONGO_URI'), db_name='test')
        def no_name():
            return {'baka': 'kaka'}
        no_name()
        db = self.conn['test']
        c = db['transaction_audit']
        result = c.find()
        self.assertEquals(result.count(), 1)
        self.assertEquals(result.next()['data']['baka'], 'kaka')

        @TransactionAudit(celery.conf.get('MONGO_URI'), db_name='test')
        def get_postal_address(arg1, arg2):
            return {'baka', 'kaka'}
        get_postal_address('dummy', '1111')
        result = c.find_one({'data': {'identity_number': '1111'}})
        self.assertEquals(result['data']['identity_number'], '1111')

        @TransactionAudit(celery.conf.get('MONGO_URI'), db_name='test')
        def send_message(arg1, arg2, arg3, arg4):
            return {'TransId': 'kaka'}
        send_message('dummy', 'mm', 'dummy', '2222')
        result = c.find_one({'data.transaction_id': 'kaka'})
        self.assertEquals(result['data']['recipient'], '2222')

        send_message('dummy', 'sms', 'dummy', '3333')
        result = c.find_one({'data.recipient': '3333'})
        self.assertEquals(result['data']['recipient'], '3333')

    def test_transaction_audit_toggle(self):
        db = self.conn['test']
        c = db['transaction_audit']
        c.remove()  # Clear database
        TransactionAudit.disable()

        @TransactionAudit(celery.conf.get('MONGO_URI'), db_name='test')
        def no_name():
            return {'baka': 'kaka'}
        no_name()

        result = c.find()
        self.assertEquals(result.count(), 0)

        TransactionAudit.enable()
        @TransactionAudit(celery.conf.get('MONGO_URI'), db_name='test')
        def no_name2():
            return {'baka': 'kaka'}
        no_name2()
        result = c.find()
        self.assertEquals(result.count(), 1)
