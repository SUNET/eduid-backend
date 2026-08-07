from datetime import timedelta

import pytest

from eduid.userdb.exceptions import DocumentOutOfSync
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

    def test_email_state_bad_attempts_defaults_to_zero(self) -> None:
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code=CodeElement.parse(application="test", code_or_element="dummy-code"),
        )
        assert email_state.bad_attempts == 0

    def test_email_state_bad_attempts_round_trips(self) -> None:
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code=CodeElement.parse(application="test", code_or_element="dummy-code"),
        )
        email_state.bad_attempts = 2
        self.resetpw_db.save(email_state, is_in_database=False)

        state = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert state is not None
        assert state.bad_attempts == 2

    def test_reserve_bad_attempt_counts_each_call(self) -> None:
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code=CodeElement.parse(application="test", code_or_element="dummy-code"),
        )
        self.resetpw_db.save(email_state, is_in_database=False)

        state = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert state is not None
        for expected in (1, 2, 3):
            assert self.resetpw_db.reserve_bad_attempt(state, max_attempts=3) == expected
            # The in-memory state tracks the database, so callers cannot act on a stale count.
            assert state.bad_attempts == expected

        reloaded = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert reloaded is not None
        assert reloaded.bad_attempts == 3

    def test_reserve_bad_attempt_refuses_once_the_cap_is_spent(self) -> None:
        """The cap is the reservation: past it, no attempt is handed out and nothing is counted."""
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code=CodeElement.parse(application="test", code_or_element="dummy-code"),
        )
        self.resetpw_db.save(email_state, is_in_database=False)

        state = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert state is not None
        for expected in (1, 2, 3):
            assert self.resetpw_db.reserve_bad_attempt(state, max_attempts=3) == expected

        assert self.resetpw_db.reserve_bad_attempt(state, max_attempts=3) is None
        # A refused reservation must not push the counter past the cap either.
        reloaded = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert reloaded is not None
        assert reloaded.bad_attempts == 3

    def test_reserve_bad_attempt_caps_guesses_that_loaded_the_same_state(self) -> None:
        """The check and the increment are one step, so parallel guesses cannot all pass it.

        This is the whole point of reserving: with a separate lockout check, every request
        holding this stale count would pass and get to compare a code, and one of them could
        hold the right one - so the cap would only bound the counter, not the guesses.
        """
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code=CodeElement.parse(application="test", code_or_element="dummy-code"),
        )
        self.resetpw_db.save(email_state, is_in_database=False)

        # Three concurrent requests load the same document before any of them writes.
        loaded = [self.resetpw_db.get_state_by_eppn("hubba-bubba") for _ in range(3)]
        assert all(state is not None for state in loaded)

        reserved = [self.resetpw_db.reserve_bad_attempt(state, max_attempts=2) for state in loaded if state]
        assert reserved == [1, 2, None]

        reloaded = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert reloaded is not None
        assert reloaded.bad_attempts == 2

    def test_reserve_bad_attempt_survives_a_concurrent_write(self) -> None:
        """A write by another request between load and reservation must not break the count.

        This is the path that would otherwise escape as a 500: the reservation is reachable
        only when a state exists, so an exception here would leak state existence.
        """
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code=CodeElement.parse(application="test", code_or_element="dummy-code"),
        )
        self.resetpw_db.save(email_state, is_in_database=False)

        loaded = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert loaded is not None

        # Another request saves the same document, bumping modified_ts.
        other = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert other is not None
        other.extra_security = {"phone_numbers": []}
        self.resetpw_db.save(other)

        # `loaded` is now stale. Pin the hazard this method exists to avoid.
        with pytest.raises(DocumentOutOfSync):
            self.resetpw_db.save(loaded)

        assert self.resetpw_db.reserve_bad_attempt(loaded, max_attempts=3) == 1

    def test_reserve_bad_attempt_leaves_modified_ts_alone(self) -> None:
        """Bad attempts must not re-arm the resend throttle or postpone the auto-expire index."""
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code=CodeElement.parse(application="test", code_or_element="dummy-code"),
        )
        self.resetpw_db.save(email_state, is_in_database=False)

        state = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert state is not None
        before = state.modified_ts
        assert before is not None

        self.resetpw_db.reserve_bad_attempt(state, max_attempts=3)

        reloaded = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert reloaded is not None
        assert reloaded.modified_ts == before

    def test_reserve_bad_attempt_does_not_resurrect_a_removed_state(self) -> None:
        """The state may be removed between loading it and reserving the attempt."""
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code=CodeElement.parse(application="test", code_or_element="dummy-code"),
        )
        self.resetpw_db.save(email_state, is_in_database=False)

        state = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert state is not None
        self.resetpw_db.remove_state(state)

        assert self.resetpw_db.reserve_bad_attempt(state, max_attempts=3) is None
        assert self.resetpw_db.get_state_by_eppn("hubba-bubba") is None

    def test_reserve_bad_attempt_on_a_document_predating_the_field(self) -> None:
        """States saved before bad_attempts existed have no field, and $lt does not match one.

        Without the $exists arm in the filter they would be locked out permanently instead of
        starting from zero.
        """
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code=CodeElement.parse(application="test", code_or_element="dummy-code"),
        )
        self.resetpw_db.save(email_state, is_in_database=False)
        self.resetpw_db._coll.update_one({"eduPersonPrincipalName": "hubba-bubba"}, {"$unset": {"bad_attempts": ""}})

        state = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert state is not None
        assert self.resetpw_db.reserve_bad_attempt(state, max_attempts=3) == 1

    def test_reset_bad_attempts_clears_the_counter(self) -> None:
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code=CodeElement.parse(application="test", code_or_element="dummy-code"),
        )
        self.resetpw_db.save(email_state, is_in_database=False)

        state = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert state is not None
        self.resetpw_db.reserve_bad_attempt(state, max_attempts=3)
        self.resetpw_db.reserve_bad_attempt(state, max_attempts=3)
        assert state.bad_attempts == 2

        self.resetpw_db.reset_bad_attempts(state)
        # In memory as well as in the database: the phone-expiry rebuild re-saves whatever the
        # in-memory state holds, so a stale count there would come straight back.
        assert state.bad_attempts == 0
        reloaded = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert reloaded is not None
        assert reloaded.bad_attempts == 0

    def test_reset_bad_attempts_survives_a_concurrent_write(self) -> None:
        """Clearing the counter must not be able to escape as a DocumentOutOfSync 500.

        It runs immediately after a correct code, on a path where the caller is entitled to
        succeed. A save()-based read-modify-write would raise here.
        """
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code=CodeElement.parse(application="test", code_or_element="dummy-code"),
        )
        self.resetpw_db.save(email_state, is_in_database=False)

        loaded = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert loaded is not None
        self.resetpw_db.reserve_bad_attempt(loaded, max_attempts=3)

        other = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert other is not None
        other.extra_security = {"phone_numbers": []}
        self.resetpw_db.save(other)

        with pytest.raises(DocumentOutOfSync):
            self.resetpw_db.save(loaded)

        self.resetpw_db.reset_bad_attempts(loaded)
        reloaded = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert reloaded is not None
        assert reloaded.bad_attempts == 0

    def test_reset_bad_attempts_leaves_modified_ts_alone(self) -> None:
        """Clearing the counter must not re-arm the resend throttle or the auto-expire index."""
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code=CodeElement.parse(application="test", code_or_element="dummy-code"),
        )
        self.resetpw_db.save(email_state, is_in_database=False)

        state = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert state is not None
        self.resetpw_db.reserve_bad_attempt(state, max_attempts=3)
        before = state.modified_ts
        assert before is not None

        self.resetpw_db.reset_bad_attempts(state)

        reloaded = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert reloaded is not None
        assert reloaded.modified_ts == before

    def test_reset_bad_attempts_does_not_resurrect_a_removed_state(self) -> None:
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code=CodeElement.parse(application="test", code_or_element="dummy-code"),
        )
        self.resetpw_db.save(email_state, is_in_database=False)

        state = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        assert state is not None
        self.resetpw_db.remove_state(state)

        self.resetpw_db.reset_bad_attempts(state)
        assert self.resetpw_db.get_state_by_eppn("hubba-bubba") is None

    def test_state_without_bad_attempts_key_loads(self) -> None:
        """Existing documents predate the field; from_dict must apply the default."""
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code=CodeElement.parse(application="test", code_or_element="dummy-code"),
        )
        data = email_state.to_dict()
        del data["bad_attempts"]

        loaded = ResetPasswordEmailState.from_dict(data)
        assert loaded.bad_attempts == 0
