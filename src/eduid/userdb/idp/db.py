"""
User and user database module.
"""

import logging

from eduid.userdb import UserDB
from eduid.userdb.db import TUserDbDocument
from eduid.userdb.exceptions import EduIDDBError
from eduid.userdb.idp.user import IdPUser

logger = logging.getLogger(__name__)


class IdPUserDb(UserDB[IdPUser]):
    def __init__(self, db_uri: str, db_name: str = "eduid_am", collection: str = "attributes") -> None:
        super().__init__(db_uri, db_name, collection=collection)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> IdPUser:
        return IdPUser.from_dict(data)

    def lookup_user(self, username: str) -> IdPUser | None:
        """
        Load IdPUser from userdb.

        :param username: Either an e-mail address or an eppn.
        :return: user found in database
        """
        user = None
        try:
            if "@" in username:
                user = self.get_user_by_mail(username.lower())
            if not user:
                user = self.get_user_by_eppn(username.lower())
        except EduIDDBError as exc:
            logger.warning(f"User lookup using {username!r} did not return a valid user: {exc!s}")
            return None

        if not user:
            logger.info(f"Unknown user: {username!r}")
            return None

        logger.debug(f"Found user {user} using {username!r}")
        return user
