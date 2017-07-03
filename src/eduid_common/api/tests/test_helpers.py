# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Flask
from copy import deepcopy
from eduid_common.api.testing import EduidAPITestCase, NEW_USER_EXAMPLE
from eduid_userdb.userdb import UserDB
from eduid_userdb.user import User
from eduid_userdb.exceptions import UserDoesNotExist
from eduid_userdb.nin import Nin
from eduid_userdb.proofing.state import NinProofingState
from eduid_userdb.proofing import NinProofingElement
from eduid_userdb.logs import ProofingLog
from eduid_userdb.logs.element import ProofingLogElement
from eduid_common.api.helpers import add_nin_to_user, verify_nin_for_user

__author__ = 'lundberg'


class NinHelpersTest(EduidAPITestCase):

    def setUp(self):
        self.test_user_nin = '200001023456'
        self.wrong_test_user_nin = '199909096789'
        super(NinHelpersTest, self).setUp()

    def load_app(self, config):
        app = Flask('test_app')
        app.central_userdb = UserDB(self.mongo_instance.get_uri(), 'eduid_am')
        app.proofing_userdb = UserDB(self.mongo_instance.get_uri(), 'test_proofing_userdb')
        app.proofing_log = ProofingLog(self.mongo_instance.get_uri(), 'test_proofing_log')
        return app

    def tearDown(self):
        self.app.central_userdb._drop_whole_collection()
        self.app.proofing_userdb._drop_whole_collection()
        self.app.proofing_log._drop_whole_collection()

    def insert_verified_user(self):
        userdata = deepcopy(NEW_USER_EXAMPLE)
        del userdata['nins']
        user = User(data=userdata)
        nin_element = Nin(number=self.test_user_nin, application='AlreadyVerifiedNinHelpersTest',
                          verified=True, created_ts=True, primary=True)
        user.nins.add(nin_element)
        user.modified_ts = True
        self.app.central_userdb.save(user, check_sync=False)
        return user.eppn

    def insert_not_verified_user(self):
        userdata = deepcopy(NEW_USER_EXAMPLE)
        del userdata['nins']
        user = User(data=userdata)
        nin_element = Nin(number=self.test_user_nin, application='AlreadyAddedNinHelpersTest',
                          verified=False, created_ts=True, primary=False)
        user.nins.add(nin_element)
        user.modified_ts = True
        self.app.central_userdb.save(user, check_sync=False)
        return user.eppn

    def insert_no_nins_user(self):
        # Replace user with one without previous proofings
        userdata = deepcopy(NEW_USER_EXAMPLE)
        del userdata['nins']
        user = User(data=userdata)
        user.modified_ts = True
        self.app.central_userdb.save(user, check_sync=False)
        return user.eppn

    def test_add_nin_to_user(self):
        eppn = self.insert_no_nins_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement(number=self.test_user_nin, application='NinHelpersTest', verified=False)
        proofing_state = NinProofingState({'eduPersonPrincipalName': eppn, 'nin': nin_element.to_dict()})
        with self.app.app_context():
            add_nin_to_user(user, proofing_state)
        user = self.app.proofing_userdb.get_user_by_eppn(eppn)
        self.assertEqual(user.nins.count, 1)
        self.assertIsNotNone(user.nins.find(self.test_user_nin))
        user_nin = user.nins.find(self.test_user_nin)
        self.assertEqual(user_nin.number, self.test_user_nin)
        self.assertEqual(user_nin.created_by, 'NinHelpersTest')
        self.assertEqual(user_nin.is_verified, False)

    def test_add_nin_to_user_existing_not_verified(self):
        eppn = self.insert_not_verified_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement(number=self.test_user_nin, application='NinHelpersTest', verified=False)
        proofing_state = NinProofingState({'eduPersonPrincipalName': eppn, 'nin': nin_element.to_dict()})
        with self.app.app_context():
            add_nin_to_user(user, proofing_state)
        with self.assertRaises(UserDoesNotExist):
            self.app.proofing_userdb.get_user_by_eppn(eppn)

    def test_add_nin_to_user_existing_verified(self):
        eppn = self.insert_verified_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement(number=self.test_user_nin, application='NinHelpersTest', verified=False)
        proofing_state = NinProofingState({'eduPersonPrincipalName': eppn, 'nin': nin_element.to_dict()})
        with self.app.app_context():
            add_nin_to_user(user, proofing_state)
        with self.assertRaises(UserDoesNotExist):
            self.app.proofing_userdb.get_user_by_eppn(eppn)

    def test_verify_nin_for_user(self):
        eppn = self.insert_no_nins_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement(number=self.test_user_nin, application='NinHelpersTest', verified=False)
        proofing_state = NinProofingState({'eduPersonPrincipalName': eppn, 'nin': nin_element.to_dict()})
        proofing_log_entry = ProofingLogElement(user, created_by=proofing_state.nin.created_by, proofing_method='test',
                                                proofing_version='2017')
        with self.app.app_context():
            verify_nin_for_user(user, self.test_user_nin, proofing_state, proofing_log_entry)
        user = self.app.proofing_userdb.get_user_by_eppn(eppn)
        self.assertEqual(user.nins.count, 1)
        self.assertIsNotNone(user.nins.find(self.test_user_nin))
        user_nin = user.nins.find(self.test_user_nin)
        self.assertEqual(user_nin.number, self.test_user_nin)
        self.assertEqual(user_nin.created_by, 'NinHelpersTest')
        self.assertEqual(user_nin.is_verified, True)
        self.assertEqual(user_nin.is_primary, True)
        self.assertEqual(user_nin.verified_by, 'NinHelpersTest')
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    def test_verify_nin_for_user_existing_not_verified(self):
        eppn = self.insert_not_verified_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement(number=self.test_user_nin, application='NinHelpersTest', verified=False)
        proofing_state = NinProofingState({'eduPersonPrincipalName': eppn, 'nin': nin_element.to_dict()})
        proofing_log_entry = ProofingLogElement(user, created_by=proofing_state.nin.created_by, proofing_method='test',
                                                proofing_version='2017')
        with self.app.app_context():
            verify_nin_for_user(user, self.test_user_nin, proofing_state, proofing_log_entry)
        user = self.app.proofing_userdb.get_user_by_eppn(eppn)
        self.assertEqual(user.nins.count, 1)
        self.assertIsNotNone(user.nins.find(self.test_user_nin))
        user_nin = user.nins.find(self.test_user_nin)
        self.assertEqual(user_nin.number, self.test_user_nin)
        self.assertEqual(user_nin.created_by, 'AlreadyAddedNinHelpersTest')
        self.assertEqual(user_nin.is_verified, True)
        self.assertEqual(user_nin.is_primary, True)
        self.assertEqual(user_nin.verified_by, 'NinHelpersTest')
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    def test_verify_nin_for_user_existing_verified(self):
        eppn = self.insert_verified_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement(number=self.test_user_nin, application='NinHelpersTest', verified=False)
        proofing_state = NinProofingState({'eduPersonPrincipalName': eppn, 'nin': nin_element.to_dict()})
        proofing_log_entry = ProofingLogElement(user, created_by=proofing_state.nin.created_by, proofing_method='test',
                                                proofing_version='2017')
        with self.app.app_context():
            verify_nin_for_user(user, self.test_user_nin, proofing_state, proofing_log_entry)
        with self.assertRaises(UserDoesNotExist):
            self.app.proofing_userdb.get_user_by_eppn(eppn)
