from datetime import datetime

from eduid.userdb.phone import PhoneNumber

dashboard_primary_phone = PhoneNumber.from_dict(
    {
        "number": "+34609609609",
        "created_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "created_by": "dashboard",
        "verified": True,
        "verified_by": "dashboard",
        "verified_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "primary": True,
    }
)


dashboard_verified_phone = PhoneNumber.from_dict(
    {
        "number": "+34607507507",
        "verified": True,
        "created_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "created_by": "dashboard",
        "verified_by": "dashboard",
        "verified_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
    }
)


dashboard_unverified_phone = PhoneNumber.from_dict(
    {
        "number": "+34 6096096096",
        "created_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "created_by": "dashboard",
        "verified": False,
        "verified_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "primary": False,
    }
)


old_primary_phone = PhoneNumber.from_dict({"mobile": "+34609609609", "primary": True, "verified": True})


old_unverified_phone = PhoneNumber.from_dict({"mobile": "+34 6096096096", "verified": False})
