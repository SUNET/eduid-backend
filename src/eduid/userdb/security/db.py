import logging

from eduid.userdb.db import TUserDbDocument
from eduid.userdb.security.user import SecurityUser
from eduid.userdb.userdb import UserDB

logger = logging.getLogger(__name__)

__author__ = "lundberg"


class SecurityUserDB(UserDB[SecurityUser]):
    def __init__(self, db_uri: str, db_name: str = "eduid_security", collection: str = "profiles"):
        super().__init__(db_uri, db_name, collection=collection)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> SecurityUser:
        return SecurityUser.from_dict(data)
