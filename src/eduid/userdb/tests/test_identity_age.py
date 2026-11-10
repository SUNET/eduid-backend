from datetime import UTC, datetime

import pytest
from dateutil.relativedelta import relativedelta

from eduid.userdb.element import ElementKey
from eduid.userdb.identity import (
    EIDASIdentity,
    EIDASLoa,
    IdentityAgeStatus,
    IdentityList,
    IdentityType,
    NinIdentity,
    PridPersistence,
    get_identity_age_status,
    identity_expires_at,
)

MAX_AGE = relativedelta(years=5)
WARNING_PERIOD = relativedelta(months=3)


def _nin(verified_ts: datetime | None, created_ts: datetime | None = None, verified: bool = True) -> NinIdentity:
    data: dict[str, object] = {"number": "197801011234", "verified": verified, "identity_type": "nin"}
    if verified_ts is not None:
        data["verified_ts"] = verified_ts
    if created_ts is not None:
        data["created_ts"] = created_ts
    return NinIdentity.from_dict(data)


def _dt(year: int, month: int, day: int) -> datetime:
    return datetime(year, month, day, tzinfo=UTC)


class TestVerifiedAt:
    def test_verified_ts_preferred(self) -> None:
        identity = _nin(verified_ts=_dt(2020, 1, 1), created_ts=_dt(2019, 1, 1))
        assert identity.verified_at == _dt(2020, 1, 1)

    def test_fallback_to_created_ts(self) -> None:
        identity = _nin(verified_ts=None, created_ts=_dt(2019, 1, 1))
        assert identity.verified_at == _dt(2019, 1, 1)

    def test_no_created_ts_in_db(self) -> None:
        identity = _nin(verified_ts=None, created_ts=None)
        assert identity.no_created_ts_in_db is True
        assert identity.verified_at is None

    def test_foreign_identity_fallback(self) -> None:
        identity = EIDASIdentity(
            prid="prid",
            prid_persistence=PridPersistence.A,
            loa=EIDASLoa.NF_HIGH,
            country_code="DE",
            date_of_birth=_dt(2000, 1, 1),
            created_ts=_dt(2018, 5, 5),
            is_verified=True,
        )
        assert identity.verified_at == _dt(2018, 5, 5)


class TestAgeStatus:
    def _status(self, identity: NinIdentity, now: datetime) -> IdentityAgeStatus:
        return get_identity_age_status(identity, now, MAX_AGE, WARNING_PERIOD)

    def test_expires_at(self) -> None:
        assert identity_expires_at(_nin(_dt(2020, 1, 1)), MAX_AGE) == _dt(2025, 1, 1)

    def test_boundaries(self) -> None:
        identity = _nin(_dt(2020, 1, 1))
        # warning window starts 2024-10-01, expiry is 2025-01-01
        assert self._status(identity, _dt(2024, 9, 30)) is IdentityAgeStatus.OK
        assert self._status(identity, _dt(2024, 10, 1)) is IdentityAgeStatus.WARN
        assert self._status(identity, _dt(2024, 12, 31)) is IdentityAgeStatus.WARN
        assert self._status(identity, _dt(2025, 1, 1)) is IdentityAgeStatus.EXPIRED
        assert self._status(identity, _dt(2030, 1, 1)) is IdentityAgeStatus.EXPIRED

    def test_leap_day(self) -> None:
        identity = _nin(_dt(2020, 2, 29))
        assert identity_expires_at(identity, MAX_AGE) == _dt(2025, 2, 28)
        assert self._status(identity, _dt(2025, 2, 27)) is IdentityAgeStatus.WARN
        assert self._status(identity, _dt(2025, 2, 28)) is IdentityAgeStatus.EXPIRED

    def test_unknown(self) -> None:
        identity = _nin(verified_ts=None, created_ts=None)
        assert identity_expires_at(identity, MAX_AGE) is None
        assert self._status(identity, _dt(2100, 1, 1)) is IdentityAgeStatus.UNKNOWN


class TestUnverify:
    def test_unverify_keeps_verified_data(self) -> None:
        identity = _nin(_dt(2020, 1, 1))
        identity.verified_by = "test"
        identities = IdentityList(elements=[identity])
        identities.unverify(IdentityType.NIN)
        nin = identities.nin
        assert nin is not None
        assert nin.is_verified is False
        assert nin.verified_ts == _dt(2020, 1, 1)
        assert nin.verified_by == "test"
        assert identities.find(ElementKey("nin")) is nin

    def test_unverify_missing(self) -> None:
        identities = IdentityList(elements=[])
        with pytest.raises(KeyError):
            identities.unverify(IdentityType.NIN)


class TestNormaliseVerifiedAt:
    def test_naive_assumed_utc_and_truncated(self) -> None:
        from eduid.userdb.identity_age.db import IdentityAgeNotificationDB

        naive = datetime(2020, 1, 1, 12, 0, 0, 123456)  # noqa: DTZ001
        assert IdentityAgeNotificationDB.normalise_verified_at(naive) == datetime(
            2020, 1, 1, 12, 0, 0, 123000, tzinfo=UTC
        )

    def test_other_timezone_converted(self) -> None:
        from datetime import timedelta, timezone

        from eduid.userdb.identity_age.db import IdentityAgeNotificationDB

        aware = datetime(2020, 1, 1, 12, 0, 0, 999999, tzinfo=timezone(timedelta(hours=2)))
        result = IdentityAgeNotificationDB.normalise_verified_at(aware)
        assert result == datetime(2020, 1, 1, 10, 0, 0, 999000, tzinfo=UTC)
        assert result.tzinfo is UTC


class TestIdentityAgeNotificationElement:
    def test_key_and_roundtrip(self) -> None:
        from eduid.userdb.identity_age.db import IdentityAgeNotification

        verified_at = datetime(2020, 1, 1, 12, 0, 0, 123000, tzinfo=UTC)
        notification = IdentityAgeNotification(
            eppn="abcd-efgh", identity_type=IdentityType.NIN, verified_at=verified_at
        )
        assert notification.key == ElementKey("nin:2020-01-01T12:00:00.123+00:00")
        restored = IdentityAgeNotification.from_dict(notification.to_dict())
        assert restored == notification
