from collections.abc import Mapping
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from eduid.common.config.base import EduIDBaseAppConfig, MsgConfigMixin
from eduid.common.config.parsers import load_config
from eduid.common.proofing_utils import get_marked_given_name
from eduid.common.rpc.exceptions import NoNavetData
from eduid.common.rpc.msg_relay import FullPostalAddress, MsgRelay
from eduid.common.testing_base import normalised_data
from eduid.userdb import NinIdentity, User
from eduid.userdb.exceptions import LockedIdentityViolation, UserDoesNotExist
from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.identity import IdentityList, IdentityType
from eduid.userdb.locked_identity import LockedIdentityList
from eduid.userdb.logs import ProofingLog
from eduid.userdb.logs.element import (
    ForeignIdProofingLogElement,
    NinEIDProofingLogElement,
    NinNavetProofingLogElement,
    NinProofingLogElement,
)
from eduid.userdb.proofing import LetterProofingStateDB, LetterProofingUserDB, NinProofingElement, ProofingUser
from eduid.userdb.proofing.state import NinProofingState
from eduid.userdb.testing import SetupConfig
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.helpers import (
    add_nin_to_user,
    set_user_names_from_foreign_id,
    set_user_names_from_nin_proofing,
    verify_nin_for_user,
)
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.session.eduid_session import SessionFactory

__author__ = "lundberg"


class HelpersTestConfig(EduIDBaseAppConfig, MsgConfigMixin):
    pass


class HelpersTestApp(EduIDBaseApp):
    def __init__(self, name: str, test_config: Mapping[str, Any], **kwargs: Any) -> None:
        self.conf = load_config(typ=HelpersTestConfig, app_name=name, ns="webapp", test_config=test_config)
        super().__init__(self.conf, **kwargs)
        self.session_interface = SessionFactory(self.conf)
        # Init databases
        self.private_userdb = LetterProofingUserDB(self.conf.mongo_uri)
        self.proofing_statedb = LetterProofingStateDB(self.conf.mongo_uri)
        self.proofing_log = ProofingLog(self.conf.mongo_uri)
        # Init celery
        self.am_relay = MagicMock()
        self.msg_relay = MsgRelay(self.conf)


class NinHelpersTest(EduidAPITestCase[HelpersTestApp]):
    def load_app(self, config: Mapping[str, Any]) -> HelpersTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        app = HelpersTestApp("testing", config)

        return app

    def setUp(self, config: SetupConfig | None = None) -> None:
        super().setUp(config=config)
        self.test_user_nin = "200001023456"
        self.wrong_test_user_nin = "199909096789"
        self.locked_test_user_nin = "197801011234"
        self.test_userdata = self.test_user.to_dict()
        self.test_proofing_user = ProofingUser.from_dict(data=self.test_userdata)

    def navet_response(self) -> FullPostalAddress:
        navet_data = self._get_all_navet_data()
        return FullPostalAddress(
            name=navet_data.person.name, official_address=navet_data.person.postal_addresses.official_address
        )

    def insert_verified_user(self, nin: str | None = None) -> User:
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        user.identities = IdentityList()
        if nin is None:
            nin = self.test_user_nin
        nin_element = NinIdentity.from_dict(
            dict(
                number=nin,
                created_by="AlreadyVerifiedNinHelpersTest",
                verified=True,
            )
        )
        user.identities.add(nin_element)
        self.app.central_userdb.save(user)
        return self.app.central_userdb.get_user_by_eppn(user.eppn)

    def insert_not_verified_user(self, nin: str | None = None) -> User:
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        user.identities = IdentityList()
        if nin is None:
            nin = self.test_user_nin
        nin_element = NinIdentity.from_dict(
            dict(
                number=nin,
                created_by="AlreadyAddedNinHelpersTest",
                verified=False,
            )
        )
        user.identities.add(nin_element)
        self.app.central_userdb.save(user)
        return self.app.central_userdb.get_user_by_eppn(user.eppn)

    def insert_not_verified_not_locked_user(self, nin: str | None = None) -> User:
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        user.identities = IdentityList()
        if nin is None:
            nin = self.test_user_nin
        nin_element = NinIdentity.from_dict(
            dict(
                number=nin,
                created_by="AlreadyAddedNinHelpersTest",
                verified=False,
            )
        )
        user.identities.add(nin_element)
        user.locked_identity = LockedIdentityList()
        self.app.central_userdb.save(user)
        return self.app.central_userdb.get_user_by_eppn(user.eppn)

    def insert_no_nins_user(self) -> User:
        # Replace user with one without previous proofings
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        user.identities = IdentityList()
        user.locked_identity = LockedIdentityList()
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
        proofing_log_entry: NinProofingLogElement,
    ) -> None:
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
        self, user: User, nin_element: NinProofingElement, proofing_log_entry: NinProofingLogElement
    ) -> None:
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
    def test_add_nin_to_user(self, mock_user_sync: MagicMock) -> None:
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

    def test_add_nin_to_user_existing_not_verified(self) -> None:
        user = self.insert_not_verified_user()
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": user.eppn, "nin": nin_element.to_dict()})
        with self.app.app_context():
            add_nin_to_user(user, proofing_state)
        with pytest.raises(UserDoesNotExist):
            self.app.private_userdb.get_user_by_eppn(user.eppn)

    def test_add_nin_to_user_existing_verified(self) -> None:
        user = self.insert_verified_user()
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": user.eppn, "nin": nin_element.to_dict()})
        with self.app.app_context():
            add_nin_to_user(user, proofing_state)
        with pytest.raises(UserDoesNotExist):
            self.app.private_userdb.get_user_by_eppn(user.eppn)

    # _test_verify_nin_for_user expects User
    @pytest.mark.filterwarnings("ignore:verify_nin_for_user:DeprecationWarning")
    @patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data")
    def test_verify_nin_for_user_navet(self, mock_reference_nin: MagicMock) -> None:
        mock_reference_nin.return_value = self.test_user_nin
        user = self.insert_no_nins_user()
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        assert nin_element.created_by
        proofing_log_entry = self._get_nin_navet_proofing_log_entry(
            user=user, created_by=nin_element.created_by, nin=nin_element.number
        )
        self._test_verify_nin_for_user(user=user, nin_element=nin_element, proofing_log_entry=proofing_log_entry)

    # _test_verify_nin_for_user expects User
    @pytest.mark.filterwarnings("ignore:verify_nin_for_user:DeprecationWarning")
    @patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data")
    def test_verify_nin_for_user_eid(self, mock_reference_nin: MagicMock) -> None:
        mock_reference_nin.return_value = None
        user = self.insert_no_nins_user()
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        assert nin_element.created_by
        proofing_log_entry = self._get_nin_eid_proofing_log_entry(
            user=user, created_by=nin_element.created_by, nin=nin_element.number
        )
        self._test_verify_nin_for_user(user=user, nin_element=nin_element, proofing_log_entry=proofing_log_entry)

    @patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data")
    def test_verify_nin_for_proofing_user_navet(self, mock_reference_nin: MagicMock) -> None:
        mock_reference_nin.return_value = None
        user = self.insert_no_nins_user()
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        assert nin_element.created_by
        proofing_log_entry = self._get_nin_navet_proofing_log_entry(
            user=user, created_by=nin_element.created_by, nin=nin_element.number
        )
        self._test_verify_nin_for_proofing_user(
            user=user, nin_element=nin_element, proofing_log_entry=proofing_log_entry
        )

    @patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data")
    def test_verify_nin_for_proofing_user_eid(self, mock_reference_nin: MagicMock) -> None:
        mock_reference_nin.return_value = None
        user = self.insert_no_nins_user()
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        assert nin_element.created_by
        proofing_log_entry = self._get_nin_eid_proofing_log_entry(
            user=user, created_by=nin_element.created_by, nin=nin_element.number
        )
        self._test_verify_nin_for_proofing_user(
            user=user, nin_element=nin_element, proofing_log_entry=proofing_log_entry
        )

    @patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data")
    def test_verify_nin_for_user_existing_not_verified(self, mock_reference_nin: MagicMock) -> None:
        mock_reference_nin.return_value = None
        user = self.insert_not_verified_not_locked_user()
        user = ProofingUser.from_user(user, self.app.private_userdb)
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

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    def test_verify_nin_no_navet_data(self, mock_get_all_navet_data: MagicMock) -> None:
        """
        Make sure that a user can be verified without navet data.
        """
        mock_get_all_navet_data.side_effect = NoNavetData

        user = self.insert_not_verified_not_locked_user()
        user = ProofingUser.from_user(user, self.app.private_userdb)
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

    @patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data")
    def test_verify_nin_for_user_existing_locked_not_verified(self, mock_reference_nin: MagicMock) -> None:
        mock_reference_nin.return_value = None
        user = self.insert_not_verified_user()
        user = ProofingUser.from_user(user, self.app.private_userdb)
        nin_element = NinProofingElement.from_dict(
            dict(number=self.locked_test_user_nin, created_by="NinHelpersTest", verified=False)
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
            user=user,
            proofing_state=proofing_state,
            number=self.locked_test_user_nin,
            created_by="NinHelpersTest",
        )

    @patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data")
    def test_verify_wrong_nin_for_user_existing_not_verified(self, mock_reference_nin: MagicMock) -> None:
        mock_reference_nin.return_value = None
        user = self.insert_not_verified_user()
        user = ProofingUser.from_user(user, self.app.private_userdb)
        nin_element = NinProofingElement.from_dict(
            dict(number=self.wrong_test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": user.eppn, "nin": nin_element.to_dict()})
        assert proofing_state.nin.created_by is not None
        assert nin_element.created_by
        proofing_log_entry = self._get_nin_navet_proofing_log_entry(
            user=user, created_by=nin_element.created_by, nin=nin_element.number
        )
        with self.app.app_context(), pytest.raises(LockedIdentityViolation):
            verify_nin_for_user(user, proofing_state, proofing_log_entry)

    @patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data")
    def test_verify_changed_nin_for_user_existing_not_verified(self, mock_reference_nin: MagicMock) -> None:
        mock_reference_nin.return_value = self.locked_test_user_nin
        user = self.insert_not_verified_user(nin=self.locked_test_user_nin)
        user = ProofingUser.from_user(user, self.app.private_userdb)
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": user.eppn, "nin": nin_element.to_dict()})
        assert proofing_state.nin.created_by is not None
        assert nin_element.created_by
        proofing_log_entry = self._get_nin_eid_proofing_log_entry(
            user=user, created_by=nin_element.created_by, nin=nin_element.number
        )
        with self.app.app_context():
            assert verify_nin_for_user(user, proofing_state, proofing_log_entry) is True
        user = self.app.private_userdb.get_user_by_eppn(user.eppn)

        self._check_nin_verified_ok(
            user=user, proofing_state=proofing_state, number=self.test_user_nin, created_by="NinHelpersTest"
        )
        # user should be updated with updated nin as it references old locked nin
        assert user.identities.nin is not None
        assert user.identities.nin.number == self.test_user_nin
        # NIN should be updated by am when saving to main DB
        assert user.replace_locked is IdentityType.NIN

    def test_verify_nin_for_user_existing_verified(self) -> None:
        user = self.insert_verified_user()
        user = ProofingUser.from_user(user, self.app.private_userdb)
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": user.eppn, "nin": nin_element.to_dict()})
        assert proofing_state.nin.created_by is not None
        assert nin_element.created_by
        proofing_log_entry = self._get_nin_eid_proofing_log_entry(
            user=user, created_by=nin_element.created_by, nin=nin_element.number
        )
        with self.app.app_context():
            assert verify_nin_for_user(user, proofing_state, proofing_log_entry) is True

    @patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data")
    def test_verify_changed_nin_for_user_existing_verified(self, mock_reference_nin: MagicMock) -> None:
        mock_reference_nin.return_value = self.locked_test_user_nin
        user = self.insert_verified_user(nin=self.locked_test_user_nin)
        user = ProofingUser.from_user(user, self.app.private_userdb)
        nin_element = NinProofingElement.from_dict(
            dict(number=self.test_user_nin, created_by="NinHelpersTest", verified=False)
        )
        proofing_state = NinProofingState.from_dict({"eduPersonPrincipalName": user.eppn, "nin": nin_element.to_dict()})
        assert proofing_state.nin.created_by is not None
        assert nin_element.created_by
        proofing_log_entry = self._get_nin_eid_proofing_log_entry(
            user=user, created_by=nin_element.created_by, nin=nin_element.number
        )
        with self.app.app_context():
            assert verify_nin_for_user(user, proofing_state, proofing_log_entry) is True
        # The user should not be updated as the old nin is locked and verified
        assert user.identities.nin is not None
        assert user.identities.nin.number == self.locked_test_user_nin
        assert user.locked_identity.nin is not None
        assert user.locked_identity.nin.number == self.locked_test_user_nin

    def test_verify_nin_with_faulty_proofing_log_element(self) -> None:
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

    def test_set_user_names_from_official_address_1(self) -> None:
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

    def test_set_user_names_from_official_address_2(self) -> None:
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

    def test_set_user_names_from_official_address_3(self) -> None:
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

    def test_set_user_names_from_official_address_4(self) -> None:
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

    def test_set_user_names_from_eid(self) -> None:
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

    def test_set_user_names_from_foreign_eid(self) -> None:
        proofing_element = self._get_foreign_proofing_log_entry(user=self.test_proofing_user)
        with self.app.app_context():
            user = set_user_names_from_foreign_id(self.test_proofing_user, proofing_element)
            assert user.given_name == "Testaren Test"
            assert user.surname == "Testsson"
            assert user.legal_name == "Testaren Test Testsson"

    @staticmethod
    def test_get_given_name_from_marking() -> None:
        assert get_marked_given_name("Jan-Erik Martin", "30") == "Martin"
        assert get_marked_given_name("Eva Mia", "20") == "Mia"
        assert get_marked_given_name("Kjell Olof", "12") == "Kjell Olof"
        assert get_marked_given_name("Hedvig Britt-Marie", "23") == "Britt-Marie"

        # From Skatteverket test data
        assert get_marked_given_name("Svante Hans-Emil", "12") == "Svante Hans"

        assert get_marked_given_name("Jan-Erik Martin", "00") == "Jan-Erik Martin"
        assert get_marked_given_name("Jan-Erik Martin", None) == "Jan-Erik Martin"
