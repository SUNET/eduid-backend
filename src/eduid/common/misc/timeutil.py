from datetime import UTC, datetime


def utc_now() -> datetime:
    """Return current time with tz=UTC"""
    return datetime.now(tz=UTC)
