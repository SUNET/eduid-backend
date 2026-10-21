from eduid.userdb.exceptions import EduIDDBError

__author__ = "lundberg"


class PayloadNotRegistered(EduIDDBError):
    """
    Exception when a payload is not registered with a QueueDB.
    """


class QueueItemExpired(EduIDDBError):
    """
    A queue item with the requested deduplication key exists but is expired, so a worker will never send it.
    """
