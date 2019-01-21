# -*- coding: utf-8 -*-
__author__ = 'lundberg'

from eduid_lookup_mobile.testing import LookupMobileMongoTestCase
from eduid_lookup_mobile.decorators import TransactionAudit


class TestTransactionAudit(LookupMobileMongoTestCase):

    def setUp(self):
        super(TestTransactionAudit, self).setUp()
        _db_name = 'eduid_lookup_mobile'
        # need to set self.mongo_uri and db for the TransactionAudit decorator
        self.mongo_uri = self.tmp_db.uri
        self.db = self.tmp_db.conn['eduid_lookup_mobile']

        self.transaction_audit = True

    def test_successfull_transaction_audit(self):
        @TransactionAudit()
        def find_mobiles_by_NIN(self, national_identity_number, number_region=None):
            return ['list', 'of', 'mobile_numbers']
        find_mobiles_by_NIN(self, '200202025678')
        c = self.db['transaction_audit']
        result = c.find()
        self.assertEquals(result.count(), 1)
        hit = result.next()
        self.assertEquals(hit['data']['national_identity_number'], '200202025678')
        self.assertTrue(hit['data']['data_returned'])
        c.remove()  # Clear database

        @TransactionAudit()
        def find_NIN_by_mobile(self, mobile_number):
            return '200202025678'
        find_NIN_by_mobile(self, '+46700011222')
        c = self.db['transaction_audit']
        result = c.find()
        self.assertEquals(result.count(), 1)
        hit = result.next()
        self.assertEquals(hit['data']['mobile_number'], '+46700011222')
        self.assertTrue(hit['data']['data_returned'])
        c.remove()  # Clear database

    def test_failed_transaction_audit(self):
        @TransactionAudit()
        def find_mobiles_by_NIN(self, national_identity_number, number_region=None):
            return []
        find_mobiles_by_NIN(self, '200202025678')
        c = self.db['transaction_audit']
        result = c.find()
        self.assertEquals(result.count(), 1)
        self.assertFalse(result.next()['data']['data_returned'])
        c.remove()  # Clear database

        @TransactionAudit()
        def find_NIN_by_mobile(self, mobile_number):
            return
        find_NIN_by_mobile(self, '+46700011222')
        c = self.db['transaction_audit']
        result = c.find()
        self.assertEquals(result.count(), 1)
        self.assertFalse(result.next()['data']['data_returned'])
        c.remove()  # Clear database

    def test_transaction_audit_toggle(self):
        c = self.db['transaction_audit']
        c.remove()  # Clear database
        TransactionAudit.disable()

        @TransactionAudit()
        def no_name(self):
            return {'baka': 'kaka'}
        no_name(self)

        result = c.find()
        self.assertEquals(result.count(), 0)

        TransactionAudit.enable()

        @TransactionAudit()
        def no_name2(self):
            return {'baka': 'kaka'}
        no_name2(self)
        result = c.find()
        self.assertEquals(result.count(), 1)
