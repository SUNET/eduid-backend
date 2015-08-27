# -*- coding: utf-8 -*-
__author__ = 'lundberg'

from eduid_am.celery import celery, get_attribute_manager
from eduid_userdb import UserDB
from eduid_userdb.testing import MongoTestCase

import unittest
@unittest.skip("Not working yet")
class TestIndexes(MongoTestCase):

    def setUp(self):
        super(TestIndexes, self).setUp(celery, get_attribute_manager)

    def test_index_setup(self):
        indexes = {
            # 'index-name': {'key': [('key', 1)], 'param1': True, 'param2': False}
            # http://docs.mongodb.org/manual/reference/method/db.collection.ensureIndex/
            'mail-index-v2': {'key': [('mail', 1)], 'unique': True, 'sparse': True},
            'eppn-index-v1': {'key': [('eduPersonPrincipalName', 1)], 'unique': True},
            'norEduPersonNIN-index-v2': {'key': [('norEduPersonNIN', 1)], 'unique': True, 'sparse': True},
            'mobile-index-v1': {'key': [('mobile.mobile', 1), ('mobile.verified', 1)]},
            'mailAliases-index-v1': {'key': [('mailAliases.email', 1), ('mailAliases.verified', 1)]}
        }
        db = UserDB(self.settings.get('MONGO_URI'))
        print db._coll.index_information()
        db.setup_indexes(indexes)
        current_indexes = db._coll.index_information()
        print current_indexes
