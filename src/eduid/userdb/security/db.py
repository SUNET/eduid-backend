import logging
from datetime import timedelta

from eduid.userdb.db import TUserDbDocument
from eduid.userdb.security.user import SecurityUser
from eduid.userdb.userdb import AutoExpiringUserDB

logger = logging.getLogger(__name__)

__author__ = "lundberg"


class SecurityUserDB(AutoExpiringUserDB[SecurityUser]):
    def __init__(
        self,
        db_uri: str,
        db_name: str = "eduid_security",
        collection: str = "profiles",
        auto_expire: timedelta | None = None,
    ) -> None:
        super().__init__(db_uri, db_name, collection=collection, auto_expire=auto_expire)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> SecurityUser:
        return SecurityUser.from_dict(data)
