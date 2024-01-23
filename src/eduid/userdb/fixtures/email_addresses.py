from datetime import datetime

from eduid.userdb.mail import MailAddress

johnsmith_example_com = MailAddress.from_dict(
    {
        "email": "johnsmith@example.com",
        "created_by": "signup",
        "created_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "verified": True,
        "verified_by": "signup",
        "verified_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "primary": True,
    }
)


johnsmith2_example_com = MailAddress.from_dict(
    {
        "email": "johnsmith2@example.com",
        "created_by": "dashboard",
        "created_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "verified": False,
        "verified_by": "dashboard",
        "verified_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "primary": False,
    }
)


johnsmith3_example_com = MailAddress.from_dict(
    {
        "email": "johnsmith3@example.com",
        "created_by": "signup",
        "created_ts": datetime.fromisoformat("2017-01-04T15:47:27"),
        "verified": True,
        "verified_by": "signup",
        "verified_ts": datetime.fromisoformat("2017-01-04T16:47:27"),
        "primary": True,
    }
)


johnsmith_example_com_old = MailAddress.from_dict({"email": "johnsmith@example.com", "verified": True, "primary": True})


johnsmith2_example_com_old = MailAddress.from_dict({"email": "johnsmith2@example.com", "verified": True})


johnsmith3_example_com_unverified = MailAddress.from_dict({"email": "johnsmith3@example.com", "verified": False})


johnsmith_example_org = MailAddress.from_dict(
    {
        "email": "johnsmith@example.org",
        "created_by": "signup",
        "created_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "verified": True,
        "verified_by": "signup",
        "verified_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "primary": True,
    }
)


johnsmith2_example_org = MailAddress.from_dict(
    {
        "email": "johnsmith2@example.org",
        "created_by": "dashboard",
        "created_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "verified": False,
        "verified_by": "dashboard",
        "verified_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "primary": False,
    }
)
