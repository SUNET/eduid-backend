from datetime import timedelta

import pytest

from eduid.userdb.reset_password import ResetPasswordEmailAndPhoneState, ResetPasswordEmailState, ResetPasswordStateDB
from eduid.userdb.reset_password.element import CodeElement
from eduid.userdb.testing import MongoTestCase


class TestResetPasswordStateDB(MongoTestCase):
    @pytest.fixture(autouse=True)
    def setup(self, setup_mongo: None) -> None:
        self.resetpw_db = ResetPasswordStateDB(self.tmp_db.uri, "eduid_reset_password")

    def test_email_state(self) -> None:
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code=CodeElement.parse(application="test", code_or_element="dummy-code"),
        )

        self.resetpw_db.save(email_state, is_in_database=False)

        state = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert state is not None
        assert state.email_address == "johnsmith@example.com"
        assert state.email_code.code == "dummy-code"
        assert state.method == "email"

        assert state.email_code.is_expired(timedelta(0))
        assert not state.email_code.is_expired(timedelta(1))

    def test_email_state_get_by_code(self) -> None:
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code=CodeElement.parse(application="test", code_or_element="dummy-code"),
        )

        self.resetpw_db.save(email_state, is_in_database=False)

        state = self.resetpw_db.get_state_by_email_code("dummy-code")
        assert state is not None
        assert state.email_address == "johnsmith@example.com"
        assert state.method == "email"
        assert state.eppn == "hubba-bubba"
        assert not state.generated_password

    def test_email_state_generated_pw(self) -> None:
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code=CodeElement.parse(application="test", code_or_element="dummy-code"),
        )

        email_state.generated_password = True
        self.resetpw_db.save(email_state, is_in_database=False)

        state = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert state is not None
        assert state.email_address == "johnsmith@example.com"
        assert state.generated_password

    def test_email_state_extra_security(self) -> None:
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code=CodeElement.parse(application="test", code_or_element="dummy-code"),
        )

        email_state.extra_security = {"phone_numbers": [{"number": "+99999999999", "primary": True, "verified": True}]}
        self.resetpw_db.save(email_state, is_in_database=False)

        state = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert state is not None
        assert state.extra_security is not None
        assert state.email_address == "johnsmith@example.com"
        assert state.extra_security["phone_numbers"][0]["number"] == "+99999999999"

    def test_email_and_phone_state(self) -> None:
        email_state = ResetPasswordEmailAndPhoneState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code=CodeElement.parse(application="test", code_or_element="dummy-code"),
            phone_number="+99999999999",
            phone_code=CodeElement.parse(application="test", code_or_element="dummy-phone-code"),
        )

        self.resetpw_db.save(email_state, is_in_database=False)

        state = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert state is not None
        assert isinstance(state, ResetPasswordEmailAndPhoneState)
        assert state.email_address == "johnsmith@example.com"
        assert state.email_code.code == "dummy-code"
        assert state.phone_number == "+99999999999"
        assert state.phone_code.code == "dummy-phone-code"
        assert state.method == "email_and_phone"
