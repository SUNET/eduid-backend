from eduid.userdb.db.base import TUserDbDocument
from eduid.userdb.user import User
from eduid.userdb.userdb import UserDB


class CleanerUser(User):
    pass


class CleanerUserDB(UserDB[CleanerUser]):
    def __init__(self, db_uri: str, db_name: str = "eduid_user_cleaner", collection: str = "profiles") -> None:
        super().__init__(db_uri, db_name, collection)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> CleanerUser:
        return CleanerUser.from_dict(data)
