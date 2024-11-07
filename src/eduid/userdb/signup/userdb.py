from datetime import timedelta

from eduid.userdb.db import TUserDbDocument
from eduid.userdb.signup import SignupUser
from eduid.userdb.userdb import UserDB

__author__ = "ft"


class SignupUserDB(UserDB[SignupUser]):
    def __init__(
        self,
        db_uri: str,
        db_name: str = "eduid_signup",
        collection: str = "registered",
        auto_expire: timedelta | None = None,
    ) -> None:
        super().__init__(db_uri, db_name, collection=collection)

        if auto_expire is not None:
            # auto expire register data
            indexes = {
                "auto-discard-modified-ts": {
                    "key": [("modified_ts", 1)],
                    "expireAfterSeconds": int(auto_expire.total_seconds()),
                },
            }
            self.setup_indexes(indexes)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> SignupUser:
        return SignupUser.from_dict(data)

    def get_user_by_mail_verification_code(self, code: str) -> SignupUser | None:
        return self._get_user_by_attr("pending_mail_address.verification_code", code)

    def get_user_by_pending_mail_address(self, mail: str) -> SignupUser | None:
        mail = mail.lower()
        return self._get_user_by_attr("pending_mail_address.email", mail)
