from pydantic import BaseModel, Field, validator
from typing import Optional

from eduid.userdb.user import User
from eduid.userdb.element import UserDBValueError
class ManagedAccount(User):
    """
    Subclass of eduid.userdb.User for managed accounts.
    """

    # def __init__(self, given_name: str, surname: str):
    #     self.set
    #     self.givenName = given_name
    #     self.surname = surname

    @validator("eppn", pre=True)
    def check_eppn(cls, v: str) -> str:
        if len(v) != 11 or not v.startswith("ma-"):
            raise UserDBValueError(f"Invalid eppn: {v}")
        return v