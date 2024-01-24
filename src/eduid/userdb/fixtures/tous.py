from datetime import datetime

from eduid.userdb.tou import ToUEvent

signup_2016_v1 = ToUEvent(
    event_id="912345678901234567890123",
    version="2016-v1",
    created_ts=datetime.fromisoformat("2017-01-04T16:47:30"),
    created_by="signup",
)
