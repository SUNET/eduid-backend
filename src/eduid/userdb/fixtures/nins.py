from datetime import datetime

from eduid.userdb.nin import Nin

dashboard_primary_nin = Nin.from_dict(
    {
        "number": "197801011234",
        "created_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "created_by": "dashboard",
        "verified": True,
        "verified_by": "dashboard",
        "verified_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "primary": True,
    }
)


dashboard_verified_nin = Nin.from_dict(
    {
        "number": "197801011235",
        "created_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "created_by": "dashboard",
        "verified": True,
        "verified_by": "dashboard",
        "verified_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "primary": False,
    }
)
