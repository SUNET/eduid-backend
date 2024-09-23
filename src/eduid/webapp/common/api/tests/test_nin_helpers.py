from collections.abc import Mapping
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from eduid.common.config.base import EduIDBaseAppConfig
from eduid.common.config.parsers import load_config
from eduid.common.rpc.msg_relay import FullPostalAddress
from eduid.common.testing_base import normalised_data
from eduid.userdb import NinIdentity, User
from eduid.userdb.exceptions import LockedIdentityViolation, UserDoesNotExist
from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.identity import IdentityList
from eduid.userdb.logs import ProofingLog
from eduid.userdb.logs.element import (
    ForeignIdProofingLogElement,
    NinEIDProofingLogElement,
    NinNavetProofingLogElement,
    TNinProofingLogElementSubclass,
)
from eduid.userdb.proofing import LetterProofingStateDB, LetterProofingUserDB, NinProofingElement, ProofingUser
from eduid.userdb.proofing.state import NinProofingState
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.helpers import (
    add_nin_to_user,
    get_marked_given_name,
    set_user_names_from_foreign_id,
    set_user_names_from_nin_proofing,
    verify_nin_for_user,
)
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.session.eduid_session import SessionFactory

__author__ = "lundberg"


class HelpersTestApp(EduIDBaseApp):
    def __init__(self, name: str, test_config: Mapping[str, Any], **kwargs: Any):
        self.conf = load_config(typ=EduIDBaseAppConfig, app_name=name, ns="webapp", test_config=test_config)
        super().__init__(self.conf, **kwargs)
        self.session_interface = SessionFactory(self.conf)
        # Init databases
        self.private_userdb = LetterProofingUserDB(self.conf.mongo_uri)
        self.proofing_statedb = LetterProofingStateDB(self.conf.mongo_uri)
        self.proofing_log = ProofingLog(self.conf.mongo_uri)
        # Init celery
        self.am_relay = MagicMock()


class NinHelpersTest(EduidAPITestCase[HelpersTestApp]):
    def load_app(self, config: Mapping[str, Any]) -> HelpersTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        app = HelpersTestApp("testing", config)

        return app

    def setUp(self, *args: Any, **kwargs: Any):
        super().setUp(*args, **kwargs)
        self.test_user_nin = "200001023456"
        self.wrong_test_user_nin = "199909096789"
        self.test_userdata = self.test_user.to_dict()
        self.test_proofing_user = ProofingUser.from_dict(data=self.test_userdata)

    def navet_response(self) -> FullPostalAddress:
        navet_data = self._get_all_navet_data()
        return FullPostalAddress(
            name=navet_data.person.name, official_address=navet_data.person.postal_addresses.official_address
        )

    def insert_verified_user(self) -> User:
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        user.identities = IdentityList()
        nin_element = NinIdentity.from_dict(
            dict(
                number=self.test_user_nin,
                created_by="AlreadyVerifiedNinHelpersTest",
                verified=True,
            )
        )
        user.identities.add(nin_element)
        self.app.central_userdb.save(user)
        return self.app.central_userdb.get_user_by_eppn(user.eppn)

    def insert_not_verified_user(self) -> User:
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        user.identities = IdentityList()
        nin_element = NinIdentity.from_dict(
            dict(
                number=self.test_user_nin,
                created_by="AlreadyAddedNinHelpersTest",
                verified=False,
            )
        )
        user.identities.add(nin_element)
        self.app.central_userdb.save(user)
        return self.app.central_userdb.get_user_by_eppn(user.eppn)

    def insert_no_nins_user(self) -> User:
        # Replace user with one without previous proofings
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        user.identities = IdentityList()
        self.app.central_userdb.save(user)
        return self.app.central_userdb.get_user_by_eppn(user.eppn)

    def _get_nin_navet_proofing_log_entry(
        self, user: User, nin: str, created_by: str, navet_data: FullPostalAddress | None = None
    ) -> NinNavetProofingLogElement:
        if navet_data is None:
            navet_data = self.navet_response()
        return NinNavetProofingLogElement(
            eppn=user.eppn,
            created_by=created_by,
            nin=nin,
            user_postal_address=navet_data,
            proofing_method="letter",
            proofing_version="2017v1",
            deregistration_information=None,
        )

    @staticmethod
    def _get_nin_eid_proofing_log_entry(user: User, nin: str, created_by: str) -> NinEIDProofingLogElement:
        return NinEIDProofingLogElement(
            eppn=user.eppn,
            created_by=created_by,
            nin=nin,
            given_name="Testaren Test",
            surname="Testsson",
            proofing_method="swedenconnect",
            proofing_version="2023v1",
        )

    @staticmethod
    def _get_foreign_proofing_log_entry(user: User) -> ForeignIdProofingLogElement:
        return ForeignIdProofingLogElement(
            eppn=user.eppn,
            created_by="test",
            given_name="Testaren Test",
            surname="Testsson",
            date_of_birth="1901-02-03",
            country_code="DE",
            proofing_method="test",
            proofing_version="2018v1",
        )

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _test_verify_nin_for_user(
        self,
        mock_user_sync: MagicMock,
        user: User,
        nin_element: NinProofingElement,
        proofing_log_entry: TNinProofingLogElementSubclass,
    ):
        """Test happy-case when calling verify_nin_for_user with a User instance (deprecated)"""
        mock_user_sync.return_value = True
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": user.eppn, "nin": nin_element.to_dict()})
        assert nin_element.created_by is not None

        with self.app.app_context():
            assert verify_nin_for_user(user, proofing_state, proofing_log_entry) is True
        # The problem with passing a User to verify_nin_for_user is that the nins list on 'user'
        # has not been updated
        assert user.identities.nin is None

        user = self.app.private_userdb.get_user_by_eppn(user.eppn)
        self._check_nin_verified_ok(user=user, proofing_state=proofing_state, number=self.test_user_nin)

    def _test_verify_nin_for_proofing_user(
        self, user: User, nin_element: NinProofingElement, proofing_log_entry: TNinProofingLogElementSubclass
    ):
        """Test happy-case when calling verify_nin_for_user with a ProofingUser instance"""
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": user.eppn, "nin": nin_element.to_dict()})
        assert proofing_state.nin.created_by is not None
        proofing_user = ProofingUser.from_user(user, self.app.private_userdb)
        # check that there is no NIN on the proofing_user before calling verify_nin_for_user
        assert proofing_user.identities.nin is None
        with self.app.app_context():
            assert verify_nin_for_user(proofing_user, proofing_state, proofing_log_entry) is True
        # check that there is a NIN there now, and that it is verified
        proofing_user = self.app.private_userdb.get_user_by_eppn(user.eppn)
        self.request_user_sync(private_user=proofing_user)  # can not get mocked user sync to work?
        self._check_nin_verified_ok(user=proofing_user, proofing_state=proofing_state, number=self.test_user_nin)

        user = self.app.central_userdb.get_user_by_eppn(user.eppn)
        assert normalised_data(user.identities.to_list_of_dicts()) == normalised_data(
            proofing_user.identities.to_list_of_dicts()
        )

        self._check_nin_verified_ok(user=user, proofing_state=proofing_state, number=self.test_user_nin)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_add_nin_to_user(self, mock_user_sync: MagicMock):
        mock_user_sync.return_value = True
        user = self.insert_no_nins_user()
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": user.eppn, "nin": nin_element.to_dict()})
        with self.app.app_context():
            add_nin_to_user(user, proofing_state)
        user = self.app.private_userdb.get_user_by_eppn(user.eppn)
        self._check_nin_not_verified(user=user, number=self.test_user_nin, created_by=proofing_state.nin.created_by)

    def test_add_nin_to_user_existing_not_verified(self):
        user = self.insert_not_verified_user()
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": user.eppn, "nin": nin_element.to_dict()})
        with self.app.app_context():
            add_nin_to_user(user, proofing_state)
        with pytest.raises(UserDoesNotExist):
            self.app.private_userdb.get_user_by_eppn(user.eppn)

    def test_add_nin_to_user_existing_verified(self):
        user = self.insert_verified_user()
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": user.eppn, "nin": nin_element.to_dict()})
        with self.app.app_context():
            add_nin_to_user(user, proofing_state)
        with pytest.raises(UserDoesNotExist):
            self.app.private_userdb.get_user_by_eppn(user.eppn)

    def test_verify_nin_for_user_navet(self):
        user = self.insert_no_nins_user()
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_log_entry = self._get_nin_navet_proofing_log_entry(
            user=user, created_by=nin_element.created_by, nin=nin_element.number
        )
        self._test_verify_nin_for_user(user=user, nin_element=nin_element, proofing_log_entry=proofing_log_entry)

    def test_verify_nin_for_user_eid(self):
        user = self.insert_no_nins_user()
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_log_entry = self._get_nin_eid_proofing_log_entry(
            user=user, created_by=nin_element.created_by, nin=nin_element.number
        )
        self._test_verify_nin_for_user(user=user, nin_element=nin_element, proofing_log_entry=proofing_log_entry)

    def test_verify_nin_for_proofing_user_navet(self):
        user = self.insert_no_nins_user()
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_log_entry = self._get_nin_navet_proofing_log_entry(
            user=user, created_by=nin_element.created_by, nin=nin_element.number
        )
        self._test_verify_nin_for_proofing_user(
            user=user, nin_element=nin_element, proofing_log_entry=proofing_log_entry
        )

    def test_verify_nin_for_proofing_user_eid(self):
        user = self.insert_no_nins_user()
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_log_entry = self._get_nin_eid_proofing_log_entry(
            user=user, created_by=nin_element.created_by, nin=nin_element.number
        )
        self._test_verify_nin_for_proofing_user(
            user=user, nin_element=nin_element, proofing_log_entry=proofing_log_entry
        )

    def test_verify_nin_for_user_existing_not_verified(self):
        user = self.insert_not_verified_user()
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": user.eppn, "nin": nin_element.to_dict()})
        assert nin_element.created_by is not None
        proofing_log_entry = self._get_nin_eid_proofing_log_entry(
            user=user, created_by=nin_element.created_by, nin=nin_element.number
        )
        with self.app.app_context():
            assert verify_nin_for_user(user, proofing_state, proofing_log_entry) is True
        user = self.app.private_userdb.get_user_by_eppn(user.eppn)

        self._check_nin_verified_ok(
            user=user, proofing_state=proofing_state, number=self.test_user_nin, created_by="AlreadyAddedNinHelpersTest"
        )

    def test_verify_wrong_nin_for_user_existing_not_verified(self):
        user = self.insert_not_verified_user()
        nin_element = NinProofingElement.from_dict(
            dict(number=self.wrong_test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": user.eppn, "nin": nin_element.to_dict()})
        assert proofing_state.nin.created_by is not None
        proofing_log_entry = self._get_nin_navet_proofing_log_entry(
            user=user, created_by=nin_element.created_by, nin=nin_element.number
        )
        with self.app.app_context():
            with pytest.raises(LockedIdentityViolation):
                verify_nin_for_user(user, proofing_state, proofing_log_entry)

    def test_verify_nin_for_user_existing_verified(self):
        user = self.insert_verified_user()
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": user.eppn, "nin": nin_element.to_dict()})
        assert proofing_state.nin.created_by is not None
        proofing_log_entry = self._get_nin_eid_proofing_log_entry(
            user=user, created_by=nin_element.created_by, nin=nin_element.number
        )
        with self.app.app_context():
            assert verify_nin_for_user(user, proofing_state, proofing_log_entry) is True

    def test_verify_nin_with_faulty_proofing_log_element(self):
        user = self.insert_no_nins_user()
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        # Create a ProofingLogElement with an empty created_by, which should be rejected
        with pytest.raises(ValidationError) as exc_info:
            self._get_nin_navet_proofing_log_entry(user=user, created_by="", nin=nin_element.number)
        assert normalised_data(exc_info.value.errors(), exclude_keys=["input", "url"]) == normalised_data(
            [
                {
                    "ctx": {"min_length": 1},
                    "loc": ["created_by"],
                    "msg": "String should have at least 1 character",
                    "type": "string_too_short",
                },
            ],
        ), f"Wrong error message: {normalised_data(exc_info.value.errors(), exclude_keys=['input', 'url'])}"

    def test_set_user_names_from_official_address_1(self):
        user = ProofingUser.from_dict(data=self.test_userdata)
        proofing_element = self._get_nin_navet_proofing_log_entry(
            user=user,
            created_by="test",
            nin="190102031234",
        )
        with self.app.app_context():
            user = set_user_names_from_nin_proofing(user, proofing_element)
            assert user.given_name == "Testaren Test"
            assert user.chosen_given_name == "Test"
            assert user.surname == "Testsson"
            assert user.legal_name == "Testaren Test Testsson"

    def test_set_user_names_from_official_address_2(self):
        _user = UserFixtures().new_user_example
        user = ProofingUser.from_dict(data=_user.to_dict())
        navet_response = self.navet_response()
        navet_response.name.given_name = "Test"
        navet_response.name.given_name_marking = "10"
        proofing_element = self._get_nin_navet_proofing_log_entry(
            user=user,
            created_by="test",
            nin="190102031234",
            navet_data=navet_response,
        )
        with self.app.app_context():
            user = set_user_names_from_nin_proofing(user, proofing_element)
            assert user.given_name == "Test"
            assert user.chosen_given_name == "Test"
            assert user.surname == "Testsson"
            assert user.legal_name == "Test Testsson"

    def test_set_user_names_from_official_address_3(self):
        _user = UserFixtures().new_user_example
        user = ProofingUser.from_dict(data=_user.to_dict())
        navet_response = self.navet_response()
        navet_response.name.given_name = "Pippilotta Viktualia Rullgardina Krusmynta Efraimsdotter"
        navet_response.name.surname = "L\xe5ngstrump"
        navet_response.name.given_name_marking = "30"
        proofing_element = self._get_nin_navet_proofing_log_entry(
            user=user,
            created_by="test",
            nin="190102031234",
            navet_data=navet_response,
        )
        with self.app.app_context():
            user = set_user_names_from_nin_proofing(user, proofing_element)
            assert user.given_name == "Pippilotta Viktualia Rullgardina Krusmynta Efraimsdotter"
            assert user.chosen_given_name == "Rullgardina"
            assert user.surname == "Långstrump"
            assert user.legal_name == "Pippilotta Viktualia Rullgardina Krusmynta Efraimsdotter Långstrump"

    def test_set_user_names_from_official_address_4(self):
        user = ProofingUser.from_dict(data=self.test_user.to_dict())
        navet_response = self.navet_response()
        navet_response.name.given_name_marking = None
        proofing_element = self._get_nin_navet_proofing_log_entry(
            user=user,
            created_by="test",
            nin="190102031234",
            navet_data=navet_response,
        )
        with self.app.app_context():
            user = set_user_names_from_nin_proofing(user, proofing_element)
            assert user.given_name == "Testaren Test"
            assert user.chosen_given_name is None
            assert user.surname == "Testsson"
            assert user.legal_name == "Testaren Test Testsson"

    def test_set_user_names_from_eid(self):
        user = ProofingUser.from_dict(data=self.test_userdata)
        proofing_element = self._get_nin_eid_proofing_log_entry(
            user=user,
            created_by="test",
            nin="190102031234",
        )
        with self.app.app_context():
            user = set_user_names_from_nin_proofing(user, proofing_element)
            assert user.given_name == "Testaren Test"
            assert user.chosen_given_name is None
            assert user.surname == "Testsson"
            assert user.legal_name == "Testaren Test Testsson"

    def test_set_user_names_from_foreign_eid(self):
        proofing_element = self._get_foreign_proofing_log_entry(user=self.test_proofing_user)
        with self.app.app_context():
            user = set_user_names_from_foreign_id(self.test_proofing_user, proofing_element)
            assert user.given_name == "Testaren Test"
            assert user.surname == "Testsson"
            assert user.legal_name == "Testaren Test Testsson"

    @staticmethod
    def test_get_given_name_from_marking():
        assert get_marked_given_name("Jan-Erik Martin", "30") == "Martin"
        assert get_marked_given_name("Eva Mia", "20") == "Mia"
        assert get_marked_given_name("Kjell Olof", "12") == "Kjell Olof"
        assert get_marked_given_name("Hedvig Britt-Marie", "23") == "Britt-Marie"

        # From Skatteverket test data
        assert get_marked_given_name("Svante Hans-Emil", "12") == "Svante Hans"

        assert get_marked_given_name("Jan-Erik Martin", "00") == "Jan-Erik Martin"
        assert get_marked_given_name("Jan-Erik Martin", None) == "Jan-Erik Martin"
