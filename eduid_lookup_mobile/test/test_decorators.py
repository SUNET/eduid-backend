# -*- coding: utf-8 -*-
__author__ = 'lundberg'

import unittest
from eduid_userdb.testing import MongoTemporaryInstance
from eduid_lookup_mobile.decorators import TransactionAudit


class TestTransactionAudit(unittest.TestCase):

    def setUp(self):
        super(TestTransactionAudit, self).setUp()
        self.db_name = 'test'
        self.tmp_db = MongoTemporaryInstance.get_instance()
        self.conn = self.tmp_db.conn
        self.port = self.tmp_db.port
        self.MONGO_URI = self.tmp_db.get_uri(self.db_name)
        TransactionAudit.db_uri = self.MONGO_URI
        TransactionAudit.enable()

    def test_successfull_transaction_audit(self):
        @TransactionAudit()
        def find_mobiles_by_NIN(self, national_identity_number, number_region=None):
            return ['list', 'of', 'mobile_numbers']
        find_mobiles_by_NIN(self, '200202025678')
        db = self.conn['test']
        c = db['transaction_audit']
        result = c.find()
        self.assertEquals(result.count(), 1)
        hit = result.next()
        self.assertEquals(hit['data']['national_identity_number'], '200202025678')
        self.assertTrue(hit['data']['success'])
        c.remove()  # Clear database

        @TransactionAudit()
        def find_NIN_by_mobile(self, mobile_number):
            return '200202025678'
        find_NIN_by_mobile(self, '+46700011222')
        db = self.conn['test']
        c = db['transaction_audit']
        result = c.find()
        self.assertEquals(result.count(), 1)
        hit = result.next()
        self.assertEquals(hit['data']['mobile_number'], '+46700011222')
        self.assertTrue(hit['data']['success'])
        c.remove()  # Clear database

    def test_failed_transaction_audit(self):
        @TransactionAudit()
        def find_mobiles_by_NIN(self, national_identity_number, number_region=None):
            return []
        find_mobiles_by_NIN(self, '200202025678')
        db = self.conn['test']
        c = db['transaction_audit']
        result = c.find()
        self.assertEquals(result.count(), 1)
        self.assertFalse(result.next()['data']['success'])
        c.remove()  # Clear database

        @TransactionAudit()
        def find_NIN_by_mobile(self, mobile_number):
            return
        find_NIN_by_mobile(self, '+46700011222')
        db = self.conn['test']
        c = db['transaction_audit']
        result = c.find()
        self.assertEquals(result.count(), 1)
        self.assertFalse(result.next()['data']['success'])
        c.remove()  # Clear database

    def test_transaction_audit_toggle(self):
        db = self.conn['test']
        c = db['transaction_audit']
        c.remove()  # Clear database
        TransactionAudit.disable()

        @TransactionAudit()
        def no_name():
            return {'baka': 'kaka'}
        no_name()

        result = c.find()
        self.assertEquals(result.count(), 0)

        TransactionAudit.enable()

        @TransactionAudit()
        def no_name2():
            return {'baka': 'kaka'}
        no_name2()
        result = c.find()
        self.assertEquals(result.count(), 1)
