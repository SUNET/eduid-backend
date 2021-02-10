# -*- coding: utf-8 -*-
from typing import Any, Dict, Mapping

from mock import MagicMock, patch

from eduid_userdb.exceptions import UserDoesNotExist
from eduid_userdb.fixtures.users import new_user_example
from eduid_userdb.logs import ProofingLog
from eduid_userdb.logs.element import NinProofingLogElement, ProofingLogElement
from eduid_userdb.nin import Nin
from eduid_userdb.proofing import LetterProofingStateDB, LetterProofingUserDB, NinProofingElement, ProofingUser
from eduid_userdb.proofing.state import NinProofingState
from eduid_userdb.user import User

from eduid_common.api.app import EduIDBaseApp
from eduid_common.api.helpers import add_nin_to_user, set_user_names_from_offical_address, verify_nin_for_user
from eduid_common.api.testing import EduidAPITestCase, normalised_data
from eduid_common.config.base import EduIDBaseAppConfig
from eduid_common.config.parsers import load_config
from eduid_common.session.eduid_session import SessionFactory

__author__ = 'lundberg'


class HelpersTestApp(EduIDBaseApp):
    def __init__(self, name: str, test_config: Mapping[str, Any], **kwargs):
        self.conf = load_config(typ=EduIDBaseAppConfig, app_name=name, ns='webapp', test_config=test_config)
        super().__init__(self.conf, **kwargs)
        self.session_interface = SessionFactory(self.conf)
        # Init databases
        self.private_userdb = LetterProofingUserDB(self.conf.mongo_uri)
        self.proofing_statedb = LetterProofingStateDB(self.conf.mongo_uri)
        self.proofing_log = ProofingLog(self.conf.mongo_uri)
        # Init celery
        self.am_relay = MagicMock()


class NinHelpersTest(EduidAPITestCase):
    def update_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Called from the parent class, so that we can update the configuration
        according to the needs of this test case.
        """
        config.update(
            {'am_broker_url': 'amqp://dummy', 'celery_config': {'result_backend': 'amqp', 'task_serializer': 'json'},}
        )
        return config

    def load_app(self, config: Mapping[str, Any]) -> HelpersTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        app = HelpersTestApp('testing', config)
        # app.register_blueprint(test_views)

        return app

    def setUp(self):
        self.test_user_nin = '200001023456'
        self.wrong_test_user_nin = '199909096789'
        self.navet_response = {
            u'Name': {u'GivenName': u'Testaren Test', u'GivenNameMarking': u'20', u'Surname': u'Testsson'},
            u'OfficialAddress': {u'Address2': u'\xd6RGATAN 79 LGH 10', u'City': u'LANDET', u'PostalCode': u'12345'},
        }
        super().setUp()

    def insert_verified_user(self):
        userdata = new_user_example.to_dict()
        del userdata['nins']
        user = User.from_dict(data=userdata)
        nin_element = Nin.from_dict(
            dict(number=self.test_user_nin, created_by='AlreadyVerifiedNinHelpersTest', verified=True, primary=True,)
        )
        user.nins.add(nin_element)
        self.app.central_userdb.save(user, check_sync=False)
        return user.eppn

    def insert_not_verified_user(self):
        userdata = new_user_example.to_dict()
        del userdata['nins']
        user = User.from_dict(data=userdata)
        nin_element = Nin.from_dict(
            dict(number=self.test_user_nin, created_by='AlreadyAddedNinHelpersTest', verified=False, primary=False,)
        )
        user.nins.add(nin_element)
        self.app.central_userdb.save(user, check_sync=False)
        return user.eppn

    def insert_no_nins_user(self):
        # Replace user with one without previous proofings
        userdata = new_user_example.to_dict()
        del userdata['nins']
        user = User.from_dict(data=userdata)
        self.app.central_userdb.save(user, check_sync=False)
        return user.eppn

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_add_nin_to_user(self, mock_user_sync):
        mock_user_sync.return_value = True
        eppn = self.insert_no_nins_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by='NinHelpersTest', verified=False)
        )
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
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by='NinHelpersTest', verified=False)
        )
        proofing_state = NinProofingState.from_dict({'eduPersonPrincipalName': eppn, 'nin': nin_element.to_dict()})
        with self.app.app_context():
            add_nin_to_user(user, proofing_state)
        with self.assertRaises(UserDoesNotExist):
            self.app.private_userdb.get_user_by_eppn(eppn)

    def test_add_nin_to_user_existing_verified(self):
        eppn = self.insert_verified_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by='NinHelpersTest', verified=False)
        )
        proofing_state = NinProofingState.from_dict({'eduPersonPrincipalName': eppn, 'nin': nin_element.to_dict()})
        with self.app.app_context():
            add_nin_to_user(user, proofing_state)
        with self.assertRaises(UserDoesNotExist):
            self.app.private_userdb.get_user_by_eppn(eppn)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_verify_nin_for_user(self, mock_user_sync):
        """ Test happy-case when calling verify_nin_for_user with a User instance (deprecated) """
        mock_user_sync.return_value = True
        eppn = self.insert_no_nins_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by='NinHelpersTest', verified=False)
        )
        proofing_state = NinProofingState.from_dict({'eduPersonPrincipalName': eppn, 'nin': nin_element.to_dict()})
        proofing_log_entry = NinProofingLogElement(
            eppn=user.eppn,
            created_by=proofing_state.nin.created_by,
            nin=proofing_state.nin.number,
            user_postal_address=self.navet_response,
            proofing_method='test',
            proofing_version='2017',
        )
        with self.app.app_context():
            assert verify_nin_for_user(user, proofing_state, proofing_log_entry) is True
        # The problem with passing a User to verify_nin_for_user is that the nins list on 'user'
        # has not been updated
        assert user.nins.find(self.test_user_nin) is False

        user = self.app.private_userdb.get_user_by_eppn(eppn)
        self.assertEqual(user.nins.count, 1)
        user_nin = user.nins.find(self.test_user_nin)
        assert user_nin is not None
        self.assertEqual(user_nin.number, self.test_user_nin)
        self.assertEqual(user_nin.created_by, 'NinHelpersTest')
        self.assertEqual(user_nin.is_verified, True)
        self.assertEqual(user_nin.is_primary, True)
        self.assertEqual(user_nin.verified_by, 'NinHelpersTest')
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_verify_nin_for_user_with_proofinguser(self, mock_user_sync):
        """ Test happy-case when calling verify_nin_for_user with a ProofingUser instance """
        mock_user_sync.return_value = True
        eppn = self.insert_no_nins_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by='NinHelpersTest', verified=False)
        )
        proofing_state = NinProofingState.from_dict({'eduPersonPrincipalName': eppn, 'nin': nin_element.to_dict()})
        proofing_log_entry = NinProofingLogElement(
            eppn=user.eppn,
            created_by=proofing_state.nin.created_by,
            nin=proofing_state.nin.number,
            user_postal_address=self.navet_response,
            proofing_method='test',
            proofing_version='2017',
        )
        proofing_user = ProofingUser.from_user(user, self.app.private_userdb)
        # check that there is no NIN on the proofing_user before calling verify_nin_for_user
        assert proofing_user.nins.find(self.test_user_nin) is False
        with self.app.app_context():
            assert verify_nin_for_user(proofing_user, proofing_state, proofing_log_entry) is True
        # check that there is a NIN there now, and that it is verified
        found_nin = proofing_user.nins.find(self.test_user_nin)
        assert found_nin is not False
        assert found_nin.is_verified is not False

        user = self.app.private_userdb.get_user_by_eppn(eppn)
        assert normalised_data(user.nins.to_list_of_dicts()) == normalised_data(proofing_user.nins.to_list_of_dicts())

        self.assertEqual(user.nins.count, 1)
        user_nin = user.nins.find(self.test_user_nin)
        assert user_nin is not None
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
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by='NinHelpersTest', verified=False)
        )
        proofing_state = NinProofingState.from_dict({'eduPersonPrincipalName': eppn, 'nin': nin_element.to_dict()})
        proofing_log_entry = NinProofingLogElement(
            eppn=user.eppn,
            created_by=proofing_state.nin.created_by,
            nin=proofing_state.nin.number,
            user_postal_address=self.navet_response,
            proofing_method='test',
            proofing_version='2017',
        )
        with self.app.app_context():
            assert verify_nin_for_user(user, proofing_state, proofing_log_entry) is True
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
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by='NinHelpersTest', verified=False)
        )
        proofing_state = NinProofingState.from_dict({'eduPersonPrincipalName': eppn, 'nin': nin_element.to_dict()})
        proofing_log_entry = ProofingLogElement(
            user, created_by=proofing_state.nin.created_by, proofing_method='test', proofing_version='2017'
        )
        with self.app.app_context():
            assert verify_nin_for_user(user, proofing_state, proofing_log_entry) is True

    def test_verify_nin_with_faulty_proofing_log_element(self):
        eppn = self.insert_no_nins_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by='NinHelpersTest', verified=False)
        )
        proofing_state = NinProofingState.from_dict({'eduPersonPrincipalName': eppn, 'nin': nin_element.to_dict()})
        # Create a ProofingLogElement with an empty created_by, which should be rejected on save in LogDB
        proofing_log_entry = NinProofingLogElement(
            eppn=user.eppn,
            created_by='',
            nin=proofing_state.nin.number,
            user_postal_address=self.navet_response,
            proofing_method='test',
            proofing_version='2017',
        )
        with self.app.app_context():
            # Verify that failure to save the proofing log element is returned to caller
            assert verify_nin_for_user(user, proofing_state, proofing_log_entry) is False
        # Validate that the user wasn't added to the private_userdb
        user = self.app.private_userdb.get_user_by_eppn(eppn, raise_on_missing=False)
        assert user is None

    def test_set_user_names_from_offical_address_1(self):
        userdata = new_user_example.to_dict()
        del userdata['displayName']
        user = ProofingUser.from_dict(data=userdata)
        proofing_element = NinProofingLogElement(
            eppn=user.eppn,
            created_by='test',
            nin='190102031234',
            user_postal_address=self.navet_response,
            proofing_method='test',
            proofing_version='2018v1',
        )
        with self.app.app_context():
            user = set_user_names_from_offical_address(user, proofing_element)
            self.assertEqual(user.given_name, 'Testaren Test')
            self.assertEqual(user.surname, 'Testsson')
            self.assertEqual(user.display_name, 'Test Testsson')

    def test_set_user_names_from_offical_address_2(self):
        userdata = new_user_example.to_dict()
        del userdata['displayName']
        user = ProofingUser.from_dict(data=userdata)
        navet_response = {
            u'Name': {u'GivenName': u'Test', u'GivenNameMarking': u'10', u'Surname': u'Testsson'},
            u'OfficialAddress': {u'Address2': u'\xd6RGATAN 79 LGH 10', u'City': u'LANDET', u'PostalCode': u'12345'},
        }
        proofing_element = NinProofingLogElement(
            eppn=user.eppn,
            created_by='test',
            nin='190102031234',
            user_postal_address=navet_response,
            proofing_method='test',
            proofing_version='2018v1',
        )
        with self.app.app_context():
            user = set_user_names_from_offical_address(user, proofing_element)
            self.assertEqual(user.given_name, 'Test')
            self.assertEqual(user.surname, 'Testsson')
            self.assertEqual(user.display_name, 'Test Testsson')

    def test_set_user_names_from_offical_address_3(self):
        userdata = new_user_example.to_dict()
        del userdata['displayName']
        user = ProofingUser.from_dict(data=userdata)
        navet_response = {
            u'Name': {
                u'GivenName': u'Pippilotta Viktualia Rullgardina Krusmynta Efraimsdotter',
                u'GivenNameMarking': u'30',
                u'Surname': u'L\xe5ngstrump',
            },
            u'OfficialAddress': {u'Address2': u'\xd6RGATAN 79 LGH 10', u'City': u'LANDET', u'PostalCode': u'12345'},
        }
        proofing_element = NinProofingLogElement(
            eppn=user.eppn,
            created_by='test',
            nin='190102031234',
            user_postal_address=navet_response,
            proofing_method='test',
            proofing_version='2018v1',
        )
        with self.app.app_context():
            user = set_user_names_from_offical_address(user, proofing_element)
            self.assertEqual(user.given_name, u'Pippilotta Viktualia Rullgardina Krusmynta Efraimsdotter')
            self.assertEqual(user.surname, u'Långstrump')
            self.assertEqual(user.display_name, u'Rullgardina Långstrump')

    def test_set_user_names_from_offical_address_4(self):
        userdata = new_user_example.to_dict()
        del userdata['displayName']
        user = ProofingUser.from_dict(data=userdata)
        navet_response = {
            u'Name': {u'GivenName': u'Testaren Test', u'Surname': u'Testsson'},
            u'OfficialAddress': {u'Address2': u'\xd6RGATAN 79 LGH 10', u'City': u'LANDET', u'PostalCode': u'12345'},
        }
        proofing_element = NinProofingLogElement(
            eppn=user.eppn,
            created_by='test',
            nin='190102031234',
            user_postal_address=navet_response,
            proofing_method='test',
            proofing_version='2018v1',
        )
        with self.app.app_context():
            user = set_user_names_from_offical_address(user, proofing_element)
            self.assertEqual(user.given_name, 'Testaren Test')
            self.assertEqual(user.surname, 'Testsson')
            self.assertEqual(user.display_name, 'Testaren Test Testsson')

    def test_set_user_names_from_offical_address_existing_display_name(self):
        userdata = new_user_example.to_dict()
        user = ProofingUser.from_dict(data=userdata)
        proofing_element = NinProofingLogElement(
            eppn=user.eppn,
            created_by='test',
            nin='190102031234',
            user_postal_address=self.navet_response,
            proofing_method='test',
            proofing_version='2018v1',
        )
        with self.app.app_context():
            user = set_user_names_from_offical_address(user, proofing_element)
            self.assertEqual(user.given_name, 'Testaren Test')
            self.assertEqual(user.surname, 'Testsson')
            self.assertEqual(user.display_name, 'John Smith')
