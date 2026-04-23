# Keep existing imports working
from eduid.userdb.db.base import TUserDbDocument
from eduid.userdb.db.sync_db import BaseDB, MongoDB, SaveResult

__all__ = [
    "BaseDB",
    "MongoDB",
    "SaveResult",
    "TUserDbDocument",
]
