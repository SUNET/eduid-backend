import logging
from datetime import timedelta

from eduid.userdb.db import TUserDbDocument
from eduid.userdb.idp.credential_user import CredentialUser
from eduid.userdb.userdb import AutoExpiringUserDB

logger = logging.getLogger(__name__)


class CredentialUserDB(AutoExpiringUserDB[CredentialUser]):
    def __init__(
        self,
        db_uri: str,
        db_name: str = "eduid_idp",
        collection: str = "credentials",
        auto_expire: timedelta | None = None,
    ) -> None:
        super().__init__(db_uri, db_name, collection=collection, auto_expire=auto_expire)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> CredentialUser:
        return CredentialUser.from_dict(data)
