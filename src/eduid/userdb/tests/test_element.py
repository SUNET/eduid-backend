from datetime import datetime
from unittest import TestCase

from eduid.userdb.element import Element, PrimaryElement, PrimaryElementViolation, VerifiedElement


class TestElements(TestCase):
    def test_create_element(self) -> None:
        elem = Element(created_by="test")

        assert elem.created_by == "test"
        assert isinstance(elem.created_ts, datetime)
        assert isinstance(elem.modified_ts, datetime)

    def test_create_element_with_created_ts(self) -> None:
        now = datetime.utcnow()
        elem = Element(created_by="test", created_ts=now)

        assert elem.created_by == "test"
        assert elem.created_ts == now
        assert isinstance(elem.modified_ts, datetime)

    def test_create_element_with_modified_ts(self) -> None:
        now = datetime.utcnow()
        elem = Element(created_by="test", modified_ts=now)

        assert elem.created_by == "test"
        assert elem.modified_ts == now
        assert isinstance(elem.modified_ts, datetime)

    def test_create_element_with_created_and_modified_ts(self) -> None:
        now = datetime.utcnow()
        elem = Element(created_by="test", modified_ts=now, created_ts=now)

        assert elem.created_by == "test"
        assert elem.created_ts == now
        assert elem.modified_ts == now

    def test_element_reset_modified_ts(self) -> None:
        now = datetime.utcnow()
        elem = Element(created_by="test", modified_ts=now, created_ts=now)

        then = datetime.utcnow()
        elem.modified_ts = then

        assert elem.modified_ts == then


class TestVerifiedElements(TestCase):
    def test_create_verified_element(self) -> None:
        elem = VerifiedElement(created_by="test")

        assert elem.created_by == "test"
        assert isinstance(elem.created_ts, datetime)
        assert isinstance(elem.modified_ts, datetime)

        assert elem.is_verified is False
        assert elem.verified_by is None
        assert elem.verified_ts is None

    def test_modify_verified_element(self) -> None:
        elem = VerifiedElement(created_by="test")
        now = datetime.utcnow()

        elem.is_verified = True
        elem.verified_by = "test"
        elem.verified_ts = now

        assert elem.created_by == "test"
        assert isinstance(elem.created_ts, datetime)
        assert isinstance(elem.modified_ts, datetime)

        assert elem.is_verified is True
        assert elem.verified_by == "test"
        assert elem.verified_ts == now

    def test_create_full_verified_element(self) -> None:
        now = datetime.utcnow()

        elem = VerifiedElement(
            created_by="test", created_ts=now, modified_ts=now, is_verified=True, verified_by="test", verified_ts=now
        )

        assert elem.created_by == "test"
        assert isinstance(elem.created_ts, datetime)
        assert isinstance(elem.modified_ts, datetime)

        assert elem.is_verified is True
        assert elem.verified_by == "test"
        assert elem.verified_ts == now


class TestPrimaryElements(TestCase):
    def test_create_primary_element(self) -> None:
        elem = PrimaryElement(created_by="test")

        assert elem.created_by == "test"
        assert isinstance(elem.created_ts, datetime)
        assert isinstance(elem.modified_ts, datetime)

        assert elem.is_verified is False
        assert elem.verified_by is None
        assert elem.verified_ts is None

        assert elem.is_primary is False

    def test_modify_primary_element(self) -> None:
        elem = PrimaryElement(created_by="test")
        now = datetime.utcnow()

        elem.is_verified = True
        elem.verified_by = "test"
        elem.verified_ts = now

        elem.is_primary = True

        assert elem.created_by == "test"
        assert isinstance(elem.created_ts, datetime)
        assert isinstance(elem.modified_ts, datetime)

        assert elem.is_verified is True
        assert elem.verified_by == "test"
        assert elem.verified_ts == now

        assert elem.is_primary is True

    def test_create_full_primary_element(self) -> None:
        now = datetime.utcnow()

        elem = PrimaryElement(
            created_by="test",
            created_ts=now,
            modified_ts=now,
            is_verified=True,
            verified_by="test",
            verified_ts=now,
            is_primary=True,
        )

        assert elem.created_by == "test"
        assert isinstance(elem.created_ts, datetime)
        assert isinstance(elem.modified_ts, datetime)

        assert elem.is_verified is True
        assert elem.verified_by == "test"
        assert elem.verified_ts == now

        assert elem.is_primary is True

    def test_unverify_primary_element(self) -> None:
        now = datetime.utcnow()

        elem = PrimaryElement(
            created_by="test",
            created_ts=now,
            modified_ts=now,
            is_verified=True,
            verified_by="test",
            verified_ts=now,
            is_primary=True,
        )
        with self.assertRaises(PrimaryElementViolation):
            elem.is_verified = False
