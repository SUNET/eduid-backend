# -*- coding: utf-8 -*-
from datetime import datetime

from eduid.userdb import EIDASIdentity, NinIdentity

__author__ = 'lundberg'


verified_nin_identity = NinIdentity.from_dict(
    {
        'number': '197801011234',
        'created_ts': datetime.fromisoformat("2022-09-02T10:23:25"),
        'created_by': 'test',
        'verified': True,
        'verified_by': 'test',
        'verified_ts': datetime.fromisoformat("2022-09-02T10:23:25"),
    }
)

unverified_nin_identity = NinIdentity.from_dict(
    {
        'number': '197901011234',
        'created_ts': datetime.fromisoformat("2022-10-02T10:23:25"),
        'created_by': 'test',
        'verified': False,
    }
)


verified_eidas_identity = EIDASIdentity.from_dict(
    {
        'prid': 'unique/prid/string/1',
        'prid_persistence': 'B',
        'date_of_birth': datetime.fromisoformat("1978-09-02T00:00:00"),
        'created_ts': datetime.fromisoformat("2022-09-02T10:23:25"),
        'created_by': 'test',
        'verified': True,
        'verified_by': 'test',
        'verified_ts': datetime.fromisoformat("2022-09-02T10:23:25"),
    }
)

unverified_eidas_identity = EIDASIdentity.from_dict(
    {
        'prid': 'unique/prid/string/2',
        'prid_persistence': 'B',
        'date_of_birth': datetime.fromisoformat("1977-09-02T00:00:00"),
        'created_ts': datetime.fromisoformat("2022-09-02T10:23:25"),
        'created_by': 'test',
    }
)
