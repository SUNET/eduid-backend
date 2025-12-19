import logging
from datetime import timedelta

from eduid.userdb.db import TUserDbDocument
from eduid.userdb.personal_data.user import PersonalDataUser
from eduid.userdb.userdb import AutoExpiringUserDB

logger = logging.getLogger(__name__)

__author__ = "lundberg"


class PersonalDataUserDB(AutoExpiringUserDB[PersonalDataUser]):
    def __init__(
        self,
        db_uri: str,
        db_name: str = "eduid_personal_data",
        collection: str = "profiles",
        auto_expire: timedelta | None = None,
    ) -> None:
        super().__init__(db_uri, db_name, collection=collection, auto_expire=auto_expire)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> PersonalDataUser:
        return PersonalDataUser.from_dict(data)
