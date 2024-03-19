from datetime import datetime

from eduid.userdb.identity import NinIdentity

dashboard_locked_nin = NinIdentity(
    number="197801011234",
    created_by="dashboard",
    created_ts=datetime.fromisoformat("2013-09-02T10:23:25"),
    is_verified=True,
)
