"""The optional facts on a Webauthn credential: absent means "not known", and nothing is written for them."""

from datetime import UTC, datetime
from typing import Any

from fido2.webauthn import AuthenticatorAttachment

from eduid.userdb.credentials import Webauthn

NEW_FIELDS = ("is_discoverable", "backup_eligible", "backup_state", "key_checked_ts", "transports")


def _credential(**kwargs: Any) -> Webauthn:
    return Webauthn(
        keyhandle="a_keyhandle",
        app_id="https://eduid.example.org",
        credential_data="a_credential_data",
        authenticator=AuthenticatorAttachment.CROSS_PLATFORM,
        description="a key",
        **kwargs,
    )


class TestWebauthnOptionalFacts:
    def test_a_credential_without_the_facts_has_none(self) -> None:
        cred = _credential()
        for name in NEW_FIELDS:
            assert getattr(cred, name) is None

    def test_nothing_is_written_for_absent_facts(self) -> None:
        # an app that has not stored any of them leaves the document as it was, so that apps that do not
        # know the fields yet can still load it
        data = _credential().to_dict()
        for name in NEW_FIELDS:
            assert name not in data

    def test_an_existing_document_round_trips_unchanged(self) -> None:
        data = _credential(authenticator_id=None).to_dict()
        assert Webauthn.from_dict(data).to_dict() == data

    def test_the_facts_round_trip(self) -> None:
        checked = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
        cred = _credential(
            is_discoverable=True,
            backup_eligible=True,
            backup_state=False,
            key_checked_ts=checked,
            transports=["usb", "nfc"],
        )
        data = cred.to_dict()
        assert data["is_discoverable"] is True
        assert data["backup_eligible"] is True
        assert data["backup_state"] is False  # False is a value, not "absent"
        assert data["key_checked_ts"] == checked
        assert data["transports"] == ["usb", "nfc"]

        loaded = Webauthn.from_dict(data)
        assert loaded == cred
        assert loaded.key_checked_ts == checked

    def test_false_is_kept_not_dropped(self) -> None:
        data = _credential(is_discoverable=False, backup_eligible=False, backup_state=False).to_dict()
        assert data["is_discoverable"] is False
        assert data["backup_eligible"] is False
        assert data["backup_state"] is False

    def test_the_facts_do_not_change_the_credential_key(self) -> None:
        # the key is what ties other data to the credential, so it must only depend on the keyhandle and data
        assert _credential().key == _credential(is_discoverable=True, transports=["usb"]).key
