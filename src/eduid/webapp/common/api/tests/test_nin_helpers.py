# -*- coding: utf-8 -*-
from typing import Any, Mapping

import pytest
from mock import MagicMock, patch
from pydantic import ValidationError

from eduid.common.config.base import EduIDBaseAppConfig
from eduid.common.config.parsers import load_config
from eduid.common.rpc.msg_relay import FullPostalAddress
from eduid.common.testing_base import normalised_data
from eduid.userdb import NinIdentity
from eduid.userdb.fixtures.users import new_user_example
from eduid.userdb.logs import ProofingLog
from eduid.userdb.logs.element import ForeignIdProofingLogElement, NinProofingLogElement
from eduid.userdb.proofing import LetterProofingStateDB, LetterProofingUserDB, NinProofingElement, ProofingUser
from eduid.userdb.proofing.state import NinProofingState
from eduid.userdb.user import User
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.helpers import (
    add_nin_to_user,
    set_user_names_from_foreign_id,
    verify_nin_for_user,
)
from eduid.common.utils import set_user_names_from_official_address
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.session.eduid_session import SessionFactory

__author__ = "lundberg"


class HelpersTestApp(EduIDBaseApp):
    def __init__(self, name: str, test_config: Mapping[str, Any], **kwargs):
        self.conf = load_config(typ=EduIDBaseAppConfig, app_name=name, ns="webapp", test_config=test_config)
        super().__init__(self.conf, **kwargs)
        self.session_interface = SessionFactory(self.conf)
        # Init databases
        self.private_userdb = LetterProofingUserDB(self.conf.mongo_uri)
        self.proofing_statedb = LetterProofingStateDB(self.conf.mongo_uri)
        self.proofing_log = ProofingLog(self.conf.mongo_uri)
        # Init celery
        self.am_relay = MagicMock()


class NinHelpersTest(EduidAPITestCase):
    def load_app(self, config: Mapping[str, Any]) -> HelpersTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        app = HelpersTestApp("testing", config)
        # app.register_blueprint(test_views)

        return app

    def setUp(self):
        self.test_user_nin = "200001023456"
        self.wrong_test_user_nin = "199909096789"
        super().setUp()

    def navet_response(self) -> FullPostalAddress:
        navet_data = self._get_all_navet_data()
        return FullPostalAddress(
            name=navet_data.person.name, official_address=navet_data.person.postal_addresses.official_address
        )

    def insert_verified_user(self):
        userdata = new_user_example.to_dict()
        del userdata["identities"]
        user = User.from_dict(data=userdata)
        nin_element = NinIdentity.from_dict(
            dict(
                number=self.test_user_nin,
                created_by="AlreadyVerifiedNinHelpersTest",
                verified=True,
            )
        )
        user.identities.add(nin_element)
        self.app.central_userdb.save(user, check_sync=False)
        return user.eppn

    def insert_not_verified_user(self):
        userdata = new_user_example.to_dict()
        del userdata["identities"]
        user = User.from_dict(data=userdata)
        nin_element = NinIdentity.from_dict(
            dict(
                number=self.test_user_nin,
                created_by="AlreadyAddedNinHelpersTest",
                verified=False,
            )
        )
        user.identities.add(nin_element)
        self.app.central_userdb.save(user, check_sync=False)
        return user.eppn

    def insert_no_nins_user(self):
        # Replace user with one without previous proofings
        userdata = new_user_example.to_dict()
        del userdata["identities"]
        user = User.from_dict(data=userdata)
        self.app.central_userdb.save(user, check_sync=False)
        return user.eppn

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_add_nin_to_user(self, mock_user_sync):
        mock_user_sync.return_value = True
        eppn = self.insert_no_nins_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": eppn, "nin": nin_element.to_dict()})
        with self.app.app_context():
            add_nin_to_user(user, proofing_state)
        user = self.app.private_userdb.get_user_by_eppn(eppn)
        self._check_nin_not_verified(user=user, number=self.test_user_nin, created_by=proofing_state.nin.created_by)

    def test_add_nin_to_user_existing_not_verified(self):
        eppn = self.insert_not_verified_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": eppn, "nin": nin_element.to_dict()})
        with self.app.app_context():
            add_nin_to_user(user, proofing_state)
        assert self.app.private_userdb.get_user_by_eppn(eppn) is None

    def test_add_nin_to_user_existing_verified(self):
        eppn = self.insert_verified_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": eppn, "nin": nin_element.to_dict()})
        with self.app.app_context():
            add_nin_to_user(user, proofing_state)
        assert self.app.private_userdb.get_user_by_eppn(eppn) is None

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_nin_for_user(self, mock_user_sync):
        """Test happy-case when calling verify_nin_for_user with a User instance (deprecated)"""
        mock_user_sync.return_value = True
        eppn = self.insert_no_nins_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": eppn, "nin": nin_element.to_dict()})
        proofing_log_entry = NinProofingLogElement(
            eppn=user.eppn,
            created_by=proofing_state.nin.created_by,
            nin=proofing_state.nin.number,
            user_postal_address=self.navet_response(),
            proofing_method="test",
            proofing_version="2017",
        )
        with self.app.app_context():
            assert verify_nin_for_user(user, proofing_state, proofing_log_entry) is True
        # The problem with passing a User to verify_nin_for_user is that the nins list on 'user'
        # has not been updated
        assert user.identities.nin is None

        user = self.app.private_userdb.get_user_by_eppn(eppn)
        self._check_nin_verified_ok(user=user, proofing_state=proofing_state, number=self.test_user_nin)

    def test_verify_nin_for_user_with_proofinguser(self):
        """Test happy-case when calling verify_nin_for_user with a ProofingUser instance"""
        eppn = self.insert_no_nins_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": eppn, "nin": nin_element.to_dict()})
        proofing_log_entry = NinProofingLogElement(
            eppn=user.eppn,
            created_by=proofing_state.nin.created_by,
            nin=proofing_state.nin.number,
            user_postal_address=self.navet_response(),
            proofing_method="test",
            proofing_version="2017",
        )
        proofing_user = ProofingUser.from_user(user, self.app.private_userdb)
        # check that there is no NIN on the proofing_user before calling verify_nin_for_user
        assert proofing_user.identities.nin is None
        with self.app.app_context():
            assert verify_nin_for_user(proofing_user, proofing_state, proofing_log_entry) is True
        # check that there is a NIN there now, and that it is verified
        proofing_user = self.app.private_userdb.get_user_by_eppn(eppn)
        self.request_user_sync(private_user=proofing_user)  # can not get mocked user sync to work?
        self._check_nin_verified_ok(user=proofing_user, proofing_state=proofing_state, number=self.test_user_nin)

        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert normalised_data(user.identities.to_list_of_dicts()) == normalised_data(
            proofing_user.identities.to_list_of_dicts()
        )

        self._check_nin_verified_ok(user=user, proofing_state=proofing_state, number=self.test_user_nin)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_nin_for_user_existing_not_verified(self, mock_user_sync):
        mock_user_sync.return_value = True
        eppn = self.insert_not_verified_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": eppn, "nin": nin_element.to_dict()})
        proofing_log_entry = NinProofingLogElement(
            eppn=user.eppn,
            created_by=proofing_state.nin.created_by,
            nin=proofing_state.nin.number,
            user_postal_address=self.navet_response(),
            proofing_method="test",
            proofing_version="2017",
        )
        with self.app.app_context():
            assert verify_nin_for_user(user, proofing_state, proofing_log_entry) is True
        user = self.app.private_userdb.get_user_by_eppn(eppn)

        self._check_nin_verified_ok(
            user=user, proofing_state=proofing_state, number=self.test_user_nin, created_by="AlreadyAddedNinHelpersTest"
        )

    def test_verify_nin_for_user_existing_verified(self):
        eppn = self.insert_verified_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": eppn, "nin": nin_element.to_dict()})
        proofing_log_entry = NinProofingLogElement(
            eppn=user.eppn,
            created_by=proofing_state.nin.created_by,
            nin=nin_element.number,
            proofing_method="test",
            proofing_version="2017",
            user_postal_address=self.navet_response(),
        )
        with self.app.app_context():
            assert verify_nin_for_user(user, proofing_state, proofing_log_entry) is True

    def test_verify_nin_with_faulty_proofing_log_element(self):
        eppn = self.insert_no_nins_user()
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": eppn, "nin": nin_element.to_dict()})
        # Create a ProofingLogElement with an empty created_by, which should be rejected
        with pytest.raises(ValidationError) as exc_info:
            NinProofingLogElement(
                eppn=user.eppn,
                created_by="",
                nin=proofing_state.nin.number,
                user_postal_address=self.navet_response(),
                proofing_method="test",
                proofing_version="2017",
            )
        assert exc_info.value.errors() == [
            {
                "ctx": {"limit_value": 1},
                "loc": ("created_by",),
                "msg": "ensure this value has at least 1 characters",
                "type": "value_error.any_str.min_length",
            }
        ]

    def test_set_user_names_from_offical_address_1(self):
        userdata = new_user_example.to_dict()
        del userdata["displayName"]
        user = ProofingUser.from_dict(data=userdata)
        proofing_element = NinProofingLogElement(
            eppn=user.eppn,
            created_by="test",
            nin="190102031234",
            user_postal_address=self.navet_response(),
            proofing_method="test",
            proofing_version="2018v1",
        )
        with self.app.app_context():
            user = set_user_names_from_official_address(user, proofing_element.user_postal_address)
            assert user.given_name == "Testaren Test"
            assert user.surname == "Testsson"
            assert user.display_name == "Test Testsson"

    def test_set_user_names_from_offical_address_2(self):
        userdata = new_user_example.to_dict()
        del userdata["displayName"]
        user = ProofingUser.from_dict(data=userdata)
        navet_response = self.navet_response()
        navet_response.name.given_name = "Test"
        navet_response.name.given_name_marking = "10"
        proofing_element = NinProofingLogElement(
            eppn=user.eppn,
            created_by="test",
            nin="190102031234",
            user_postal_address=navet_response,
            proofing_method="test",
            proofing_version="2018v1",
        )
        with self.app.app_context():
            user = set_user_names_from_official_address(user, proofing_element.user_postal_address)
            assert user.given_name == "Test"
            assert user.surname == "Testsson"
            assert user.display_name == "Test Testsson"

    def test_set_user_names_from_offical_address_3(self):
        userdata = new_user_example.to_dict()
        del userdata["displayName"]
        user = ProofingUser.from_dict(data=userdata)
        navet_response = self.navet_response()
        navet_response.name.given_name = "Pippilotta Viktualia Rullgardina Krusmynta Efraimsdotter"
        navet_response.name.surname = "L\xe5ngstrump"
        navet_response.name.given_name_marking = "30"
        proofing_element = NinProofingLogElement(
            eppn=user.eppn,
            created_by="test",
            nin="190102031234",
            user_postal_address=navet_response,
            proofing_method="test",
            proofing_version="2018v1",
        )
        with self.app.app_context():
            user = set_user_names_from_official_address(user, proofing_element.user_postal_address)
            assert user.given_name == "Pippilotta Viktualia Rullgardina Krusmynta Efraimsdotter"
            assert user.surname == "Långstrump"
            assert user.display_name == "Rullgardina Långstrump"

    def test_set_user_names_from_offical_address_4(self):
        userdata = new_user_example.to_dict()
        del userdata["displayName"]
        user = ProofingUser.from_dict(data=userdata)
        navet_data = self.navet_response()
        navet_data.name.given_name_marking = None
        proofing_element = NinProofingLogElement(
            eppn=user.eppn,
            created_by="test",
            nin="190102031234",
            user_postal_address=navet_data,
            proofing_method="test",
            proofing_version="2018v1",
        )
        with self.app.app_context():
            user = set_user_names_from_official_address(user, proofing_element.user_postal_address)
            assert user.given_name == "Testaren Test"
            assert user.surname == "Testsson"
            assert user.display_name == "Testaren Test Testsson"

    def test_set_user_names_from_foreign_eid(self):
        userdata = new_user_example.to_dict()
        user = ProofingUser.from_dict(data=userdata)
        proofing_element = ForeignIdProofingLogElement(
            eppn=user.eppn,
            created_by="test",
            given_name="Testaren Test",
            surname="Testsson",
            date_of_birth="1901-02-03",
            country_code="DE",
            proofing_method="test",
            proofing_version="2018v1",
        )
        with self.app.app_context():
            user = set_user_names_from_foreign_id(user, proofing_element)
            assert user.given_name == "Testaren Test"
            assert user.surname == "Testsson"
            assert user.display_name == "Testaren Test Testsson"

    def test_set_user_names_from_foreign_eid_existing_display_name(self):
        userdata = new_user_example.to_dict()
        user = ProofingUser.from_dict(data=userdata)
        proofing_element = ForeignIdProofingLogElement(
            eppn=user.eppn,
            created_by="test",
            given_name="Testaren Test",
            surname="Testsson",
            date_of_birth="1901-02-03",
            country_code="DE",
            proofing_method="test",
            proofing_version="2018v1",
        )
        with self.app.app_context():
            user = set_user_names_from_foreign_id(user, proofing_element)
            assert user.given_name == "Testaren Test"
            assert user.surname == "Testsson"
            assert user.display_name == "Testaren Test Testsson"

    def test_set_user_names_from_foreign_eid_custom_display_name(self):
        userdata = new_user_example.to_dict()
        user = ProofingUser.from_dict(data=userdata)
        proofing_element = ForeignIdProofingLogElement(
            eppn=user.eppn,
            created_by="test",
            given_name="Testaren Test",
            surname="Testsson",
            date_of_birth="1901-02-03",
            country_code="DE",
            proofing_method="test",
            proofing_version="2018v1",
        )
        with self.app.app_context():
            user = set_user_names_from_foreign_id(user, proofing_element, display_name="Test Testsson")
            assert user.given_name == "Testaren Test"
            assert user.surname == "Testsson"
            assert user.display_name == "Test Testsson"
