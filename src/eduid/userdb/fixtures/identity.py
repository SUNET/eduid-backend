from datetime import datetime

from eduid.userdb import EIDASIdentity, NinIdentity
from eduid.userdb.identity import EIDASLoa, PridPersistence, SvipeIdentity

__author__ = "lundberg"

verified_nin_identity = NinIdentity(
    number="197801011234",
    created_ts=datetime.fromisoformat("2022-09-02T10:23:25"),
    created_by="test",
    is_verified=True,
    verified_by="test",
    verified_ts=datetime.fromisoformat("2022-09-02T10:23:25"),
)

unverified_nin_identity = NinIdentity(
    number="197801011234",
    created_ts=datetime.fromisoformat("2022-10-02T10:23:25"),
    created_by="test",
    is_verified=False,
)


verified_eidas_identity = EIDASIdentity(
    prid="unique/prid/string/1",
    prid_persistence=PridPersistence.B,
    loa=EIDASLoa.NF_SUBSTANTIAL,
    date_of_birth=datetime.fromisoformat("1978-09-02T00:00:00"),
    country_code="DE",
    created_ts=datetime.fromisoformat("2022-09-02T10:23:25"),
    created_by="test",
    is_verified=True,
    verified_by="test",
    verified_ts=datetime.fromisoformat("2022-09-02T10:23:25"),
)

unverified_eidas_identity = EIDASIdentity(
    prid="unique/prid/string/2",
    prid_persistence=PridPersistence.B,
    loa=EIDASLoa.NF_SUBSTANTIAL,
    date_of_birth=datetime.fromisoformat("1977-09-02T00:00:00"),
    country_code="DE",
    created_ts=datetime.fromisoformat("2022-09-02T10:23:25"),
    created_by="test",
)


verified_svipe_identity = SvipeIdentity(
    svipe_id="unique-svipe-id-1",
    administrative_number="1234567890",
    date_of_birth=datetime.fromisoformat("1978-09-02T00:00:00"),
    country_code="DE",
    created_ts=datetime.fromisoformat("2022-09-02T10:23:25"),
    created_by="test",
    is_verified=True,
    verified_by="test",
    verified_ts=datetime.fromisoformat("2022-09-02T10:23:25"),
)

unverified_svipe_identity = SvipeIdentity(
    svipe_id="unique-svipe-id-2",
    administrative_number="0123456789",
    date_of_birth=datetime.fromisoformat("1977-09-02T00:00:00"),
    country_code="DE",
    created_ts=datetime.fromisoformat("2022-09-02T10:23:25"),
    created_by="test",
)
