from datetime import datetime, timezone


def utc_now() -> datetime:
    """ Return current time with tz=UTC """
    return datetime.now(tz=timezone.utc)
