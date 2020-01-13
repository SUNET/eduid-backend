# -*- coding: utf-8 -*-

from copy import deepcopy

from eduid_userdb.data_samples import NEW_USER_EXAMPLE
from eduid_userdb.exceptions import UserDoesNotExist
from eduid_userdb.logs import ProofingLog
from eduid_userdb.logs.element import ProofingLogElement, NinProofingLogElement
from eduid_userdb.nin import Nin
from eduid_userdb.proofing import NinProofingElement
from eduid_userdb.proofing import ProofingUser
from eduid_userdb.proofing.state import NinProofingState
from eduid_userdb.user import User
from eduid_userdb.userdb import UserDB
from mock import patch

from eduid_common.api.am import init_relay
from eduid_common.api.helpers import add_nin_to_user, verify_nin_for_user, set_user_names_from_offical_address
from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.letter_proofing.settings.common import LetterProofingConfig
from eduid_webapp.letter_proofing.app import LetterProofingApp

__author__ = 'lundberg'


class NinHelpersTest(EduidAPITestCase):

    def setUp(self):
        self.test_user_nin = '200001023456'
        self.wrong_test_user_nin = '199909096789'
        self.navet_response = {
            u'Name': {
                u'GivenName': u'Testaren Test',
                u'GivenNameMarking': u'20',
                u'Surname': u'Testsson'
            },
            u'OfficialAddress': {
                u'Address2': u'\xd6RGATAN 79 LGH 10',
                u'City': u'LANDET',
                u'PostalCode': u'12345'
            }
        }
        super(NinHelpersTest, self).setUp()

    def load_app(self, config):
        app = LetterProofingApp('test_app', config)
        return app

    def update_config(self, config):
        config.update({
            'am_broker_url': 'amqp://dummy',
            'celery_config': {
                'result_backend': 'amqp',
                'task_serializer': 'json'
            },
        })
        return config

    def tearDown(self):
        self.app.central_userdb._drop_whole_collection()
        self.app.private_userdb._drop_whole_collection()
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

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_add_nin_to_user(self, mock_user_sync):
        mock_user_sync.return_value = True
        eppn = self.insert_no_nins_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement(number=self.test_user_nin, application='NinHelpersTest', verified=False)
        proofing_state = NinProofingState.from_dict({'eduPersonPrincipalName': eppn, 'nin': nin_element.to_dict()})
        with self.app.app_context():
            add_nin_to_user(user, proofing_state)
        user = self.app.private_userdb.get_user_by_eppn(eppn)
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
        proofing_state = NinProofingState.from_dict({'eduPersonPrincipalName': eppn, 'nin': nin_element.to_dict()})
        with self.app.app_context():
            add_nin_to_user(user, proofing_state)
        with self.assertRaises(UserDoesNotExist):
            self.app.private_userdb.get_user_by_eppn(eppn)

    def test_add_nin_to_user_existing_verified(self):
        eppn = self.insert_verified_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement(number=self.test_user_nin, application='NinHelpersTest', verified=False)
        proofing_state = NinProofingState.from_dict({'eduPersonPrincipalName': eppn, 'nin': nin_element.to_dict()})
        with self.app.app_context():
            add_nin_to_user(user, proofing_state)
        with self.assertRaises(UserDoesNotExist):
            self.app.private_userdb.get_user_by_eppn(eppn)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_verify_nin_for_user(self, mock_user_sync):
        mock_user_sync.return_value = True
        eppn = self.insert_no_nins_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement(number=self.test_user_nin, application='NinHelpersTest', verified=False)
        proofing_state = NinProofingState.from_dict({'eduPersonPrincipalName': eppn, 'nin': nin_element.to_dict()})
        proofing_log_entry = NinProofingLogElement(user, created_by=proofing_state.nin.created_by,
                                                   nin=proofing_state.nin.number,
                                                   user_postal_address=self.navet_response, proofing_method='test',
                                                   proofing_version='2017')
        with self.app.app_context():
            verify_nin_for_user(user, proofing_state, proofing_log_entry)
        user = self.app.private_userdb.get_user_by_eppn(eppn)
        self.assertEqual(user.nins.count, 1)
        self.assertIsNotNone(user.nins.find(self.test_user_nin))
        user_nin = user.nins.find(self.test_user_nin)
        self.assertEqual(user_nin.number, self.test_user_nin)
        self.assertEqual(user_nin.created_by, 'NinHelpersTest')
        self.assertEqual(user_nin.is_verified, True)
        self.assertEqual(user_nin.is_primary, True)
        self.assertEqual(user_nin.verified_by, 'NinHelpersTest')
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_verify_nin_for_user_existing_not_verified(self, mock_user_sync):
        mock_user_sync.return_value = True
        eppn = self.insert_not_verified_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement(number=self.test_user_nin, application='NinHelpersTest', verified=False)
        proofing_state = NinProofingState.from_dict({'eduPersonPrincipalName': eppn, 'nin': nin_element.to_dict()})
        proofing_log_entry = NinProofingLogElement(user, created_by=proofing_state.nin.created_by,
                                                   nin=proofing_state.nin.number,
                                                   user_postal_address=self.navet_response, proofing_method='test',
                                                   proofing_version='2017')
        with self.app.app_context():
            verify_nin_for_user(user, proofing_state, proofing_log_entry)
        user = self.app.private_userdb.get_user_by_eppn(eppn)
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
        proofing_state = NinProofingState.from_dict({'eduPersonPrincipalName': eppn, 'nin': nin_element.to_dict()})
        proofing_log_entry = ProofingLogElement(user, created_by=proofing_state.nin.created_by, proofing_method='test',
                                                proofing_version='2017')
        with self.app.app_context():
            verify_nin_for_user(user, proofing_state, proofing_log_entry)

    def test_set_user_names_from_offical_address_1(self):
        userdata = deepcopy(NEW_USER_EXAMPLE)
        del userdata['displayName']
        user = ProofingUser(data=userdata)
        proofing_element = NinProofingLogElement(user, created_by='test', nin='190102031234',
                                                 user_postal_address=self.navet_response, proofing_method='test',
                                                 proofing_version='2018v1')
        with self.app.app_context():
            user = set_user_names_from_offical_address(user, proofing_element)
            self.assertEqual(user.given_name, 'Testaren Test')
            self.assertEqual(user.surname, 'Testsson')
            self.assertEqual(user.display_name, 'Test Testsson')

    def test_set_user_names_from_offical_address_2(self):
        userdata = deepcopy(NEW_USER_EXAMPLE)
        del userdata['displayName']
        user = ProofingUser(data=userdata)
        navet_response = {
            u'Name':
                {
                    u'GivenName': u'Test',
                    u'GivenNameMarking': u'10',
                    u'Surname': u'Testsson'
                },
            u'OfficialAddress': {u'Address2': u'\xd6RGATAN 79 LGH 10',
                                 u'City': u'LANDET',
                                 u'PostalCode': u'12345'
                                 }
        }
        proofing_element = NinProofingLogElement(user, created_by='test', nin='190102031234',
                                                 user_postal_address=navet_response, proofing_method='test',
                                                 proofing_version='2018v1')
        with self.app.app_context():
            user = set_user_names_from_offical_address(user, proofing_element)
            self.assertEqual(user.given_name, 'Test')
            self.assertEqual(user.surname, 'Testsson')
            self.assertEqual(user.display_name, 'Test Testsson')

    def test_set_user_names_from_offical_address_3(self):
        userdata = deepcopy(NEW_USER_EXAMPLE)
        del userdata['displayName']
        user = ProofingUser(data=userdata)
        navet_response = {
            u'Name':
                {
                    u'GivenName': u'Pippilotta Viktualia Rullgardina Krusmynta Efraimsdotter',
                    u'GivenNameMarking': u'30',
                    u'Surname': u'L\xe5ngstrump'
                },
            u'OfficialAddress': {u'Address2': u'\xd6RGATAN 79 LGH 10',
                                 u'City': u'LANDET',
                                 u'PostalCode': u'12345'
                                 }
        }
        proofing_element = NinProofingLogElement(user, created_by='test', nin='190102031234',
                                                 user_postal_address=navet_response, proofing_method='test',
                                                 proofing_version='2018v1')
        with self.app.app_context():
            user = set_user_names_from_offical_address(user, proofing_element)
            self.assertEqual(user.given_name, u'Pippilotta Viktualia Rullgardina Krusmynta Efraimsdotter')
            self.assertEqual(user.surname, u'Långstrump')
            self.assertEqual(user.display_name, u'Rullgardina Långstrump')

    def test_set_user_names_from_offical_address_4(self):
        userdata = deepcopy(NEW_USER_EXAMPLE)
        del userdata['displayName']
        user = ProofingUser(data=userdata)
        navet_response = {
            u'Name':
                {
                    u'GivenName': u'Testaren Test',
                    u'Surname': u'Testsson'
                },
            u'OfficialAddress': {u'Address2': u'\xd6RGATAN 79 LGH 10',
                                 u'City': u'LANDET',
                                 u'PostalCode': u'12345'
                                 }
        }
        proofing_element = NinProofingLogElement(user, created_by='test', nin='190102031234',
                                                 user_postal_address=navet_response, proofing_method='test',
                                                 proofing_version='2018v1')
        with self.app.app_context():
            user = set_user_names_from_offical_address(user, proofing_element)
            self.assertEqual(user.given_name, 'Testaren Test')
            self.assertEqual(user.surname, 'Testsson')
            self.assertEqual(user.display_name, 'Testaren Test Testsson')

    def test_set_user_names_from_offical_address_existing_display_name(self):
        userdata = deepcopy(NEW_USER_EXAMPLE)
        user = ProofingUser(data=userdata)
        proofing_element = NinProofingLogElement(user, created_by='test', nin='190102031234',
                                                 user_postal_address=self.navet_response, proofing_method='test',
                                                 proofing_version='2018v1')
        with self.app.app_context():
            user = set_user_names_from_offical_address(user, proofing_element)
            self.assertEqual(user.given_name, 'Testaren Test')
            self.assertEqual(user.surname, 'Testsson')
            self.assertEqual(user.display_name, 'John Smith')
