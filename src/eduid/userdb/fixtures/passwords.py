from datetime import datetime

from bson import ObjectId

from eduid.userdb.credentials.password import Password

signup_password = Password(
    credential_id=str(ObjectId("112345678901234567890123")),
    salt="$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$",
    created_by="signup",
    created_ts=datetime.fromisoformat("2013-09-02T10:23:25"),
)


signup_password_2 = Password(
    credential_id=str(ObjectId("a12345678901234567890123")),
    salt="$NDNv1H1$2d465dcc9c68075aa095b646a98e2e3edb1c612c175ebdeaca6c9a55a0457833$32$32$",
    created_by="signup",
    created_ts=datetime.fromisoformat("2017-01-04T16:47:30"),
)


old_password = Password.from_dict(
    {
        "id": ObjectId("112345678901234567890123"),
        "salt": "$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$",
        "source": "signup",
        "created_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
    }
)
