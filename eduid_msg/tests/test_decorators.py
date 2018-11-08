# -*- encoding: utf-8 -*-

from eduid_userdb.testing import MongoTestCase
from eduid_msg.tests import mock_celery, mock_get_attribute_manager
from eduid_msg.celery import celery
from eduid_msg.decorators import TransactionAudit
import pkg_resources


class TestTransactionAudit(MongoTestCase):
    def setUp(self):
        super(TestTransactionAudit, self).setUp(celery=mock_celery(), get_attribute_manager=mock_get_attribute_manager)
        TransactionAudit.enable()
        data_dir = pkg_resources.resource_filename(__name__, 'data')
        settings = {
            'BROKER_TRANSPORT': 'memory',
            'BROKER_URL': 'memory://',
            'CELERY_EAGER_PROPAGATES_EXCEPTIONS': True,
            'CELERY_ALWAYS_EAGER': True,
            'CELERY_RESULT_BACKEND': "cache",
            'CELERY_CACHE_BACKEND': 'memory',
            'MONGO_URI': self.tmp_db.uri,
            'MONGO_DBNAME': 'test',
            'SMS_ACC': 'foo',
            'SMS_KEY': 'bar',
            'SMS_SENDER': 'Test sender',
            'TEMPLATE_DIR': data_dir,
            'MESSAGE_RATE_LIMIT': '2/m',
        }
        celery.conf.update(settings)

    def test_transaction_audit(self):
        @TransactionAudit(celery.conf.get('MONGO_URI'), db_name='test')
        def no_name():
            return {'baka': 'kaka'}
        no_name()
        db = self.tmp_db.conn['test']
        c = db['transaction_audit']
        result = c.find()
        self.assertEquals(result.count(), 1)
        self.assertEquals(result.next()['data']['baka'], 'kaka')

        @TransactionAudit(celery.conf.get('MONGO_URI'), db_name='test')
        def _get_navet_data(arg1, arg2):
            return {'baka', 'kaka'}
        _get_navet_data('dummy', '1111')
        result = c.find_one({'data': {'identity_number': '1111'}})
        self.assertEquals(result['data']['identity_number'], '1111')

        @TransactionAudit(celery.conf.get('MONGO_URI'), db_name='test')
        def send_message(_self, message_type, reference, message_dict, recipient, template, language, subject=None):
            return 'kaka'
        send_message('dummy', 'mm', 'reference', 'dummy', '2222', 'template', 'lang')
        result = c.find_one({'data.transaction_id': 'kaka'})
        self.assertEquals(result['data']['recipient'], '2222')
        self.assertEquals(result['data']['audit_reference'], 'reference')
        self.assertEquals(result['data']['template'], 'template')

        send_message('dummy', 'sms', 'reference', 'dummy', '3333', 'template', 'lang')
        result = c.find_one({'data.recipient': '3333'})
        self.assertEquals(result['data']['recipient'], '3333')
        self.assertEquals(result['data']['audit_reference'], 'reference')
        self.assertEquals(result['data']['template'], 'template')

    def test_transaction_audit_toggle(self):
        db = self.tmp_db.conn['test']
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
