import logging

from eduid.userdb.db import TUserDbDocument
from eduid.userdb.personal_data.user import PersonalDataUser
from eduid.userdb.userdb import UserDB

logger = logging.getLogger(__name__)

__author__ = "lundberg"


class PersonalDataUserDB(UserDB[PersonalDataUser]):
    def __init__(self, db_uri: str, db_name: str = "eduid_personal_data", collection: str = "profiles") -> None:
        super().__init__(db_uri, db_name, collection=collection)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> PersonalDataUser:
        return PersonalDataUser.from_dict(data)
