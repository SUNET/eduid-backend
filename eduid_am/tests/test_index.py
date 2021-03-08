# -*- coding: utf-8 -*-
__author__ = 'lundberg'

import unittest

from eduid_userdb import UserDB

from eduid_am.testing import AMTestCase


@unittest.skip("Not working yet")
class TestIndexes(AMTestCase):
    def setUp(self):
        super(TestIndexes, self).setUp()

    def test_index_setup(self):
        indexes = {
            # 'index-name': {'key': [('key', 1)], 'param1': True, 'param2': False}
            # http://docs.mongodb.org/manual/reference/method/db.collection.ensureIndex/
            'mail-index-v2': {'key': [('mail', 1)], 'unique': True, 'sparse': True},
            'eppn-index-v1': {'key': [('eduPersonPrincipalName', 1)], 'unique': True},
            'norEduPersonNIN-index-v2': {'key': [('norEduPersonNIN', 1)], 'unique': True, 'sparse': True},
            'mobile-index-v1': {'key': [('mobile.mobile', 1), ('mobile.verified', 1)]},
            'mailAliases-index-v1': {'key': [('mailAliases.email', 1), ('mailAliases.verified', 1)]},
        }
        db = UserDB(self.settings.mongo_uri)
        print(db._coll.index_information())
        db.setup_indexes(indexes)
        current_indexes = db._coll.index_information()
        print(current_indexes)
