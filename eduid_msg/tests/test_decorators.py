# -*- encoding: utf-8 -*-
from __future__ import absolute_import

from eduid_msg.testing import MsgMongoTestCase
from eduid_msg.decorators import TransactionAudit


class TestTransactionAudit(MsgMongoTestCase):
    def setUp(self, init_msg=True):
        super(TestTransactionAudit, self).setUp(init_msg=init_msg)
        TransactionAudit.enable()

    def test_transaction_audit(self):
        @TransactionAudit(self.msg_settings.get('MONGO_URI'), db_name='test')
        def no_name():
            return {'baka': 'kaka'}
        no_name()
        db = self.tmp_db.conn['test']
        c = db['transaction_audit']
        result = c.find()
        self.assertEquals(result.count(), 1)
        self.assertEquals(result.next()['data']['baka'], 'kaka')

        @TransactionAudit(self.msg_settings.get('MONGO_URI'), db_name='test')
        def _get_navet_data(arg1, arg2):
            return {'baka', 'kaka'}
        _get_navet_data('dummy', '1111')
        result = c.find_one({'data': {'identity_number': '1111'}})
        self.assertEquals(result['data']['identity_number'], '1111')

        @TransactionAudit(self.msg_settings.get('MONGO_URI'), db_name='test')
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

        @TransactionAudit(self.msg_settings.get('MONGO_URI'), db_name='test')
        def no_name():
            return {'baka': 'kaka'}
        no_name()

        result = c.find()
        self.assertEquals(result.count(), 0)

        TransactionAudit.enable()
        @TransactionAudit(self.msg_settings.get('MONGO_URI'), db_name='test')
        def no_name2():
            return {'baka': 'kaka'}
        no_name2()
        result = c.find()
        self.assertEquals(result.count(), 1)
