__author__ = "masv"

from datetime import datetime

from bson import ObjectId

from eduid.userdb.meta import Meta

cleaned_skv_meta = Meta(
    version=ObjectId("987654321098765432103210"),
    cleaning={
        "skv": datetime.fromisoformat("2022-09-02T10:23:25"),
    },
)
