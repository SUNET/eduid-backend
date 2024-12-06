from eduid.userdb import User
from eduid.userdb.identity import IdentityType

__author__ = "lundberg"


class ProofingUser(User):
    replace_locked: IdentityType | None = None
