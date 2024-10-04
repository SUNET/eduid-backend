__author__ = "ft"


from eduid.userdb.actions.tou import ToUUser
from eduid.userdb.db import TUserDbDocument
from eduid.userdb.userdb import UserDB


class ToUUserDB(UserDB[ToUUser]):
    def __init__(self, db_uri: str, db_name: str = "eduid_actions", collection: str = "tou") -> None:
        super().__init__(db_uri, db_name, collection)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> ToUUser:
        return ToUUser.from_dict(data)
