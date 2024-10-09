"""
Some data structures that causes import loops if they are defined in db.py.
"""

from enum import StrEnum
from typing import NewType


class OtherDeviceState(StrEnum):
    NEW = "NEW"  # only used device #1 so far
    IN_PROGRESS = "IN_PROGRESS"  # device #2 has 'grabbed' the request
    AUTHENTICATED = "AUTHENTICATED"  # device #2 is finished with the request (successfully)
    FINISHED = "FINISHED"  # the correct response code was provided on device #1
    ABORTED = "ABORTED"  # either device has aborted the request
    DENIED = "DENIED"  # too many attempts have been made to provide the response_code on device #1


OtherDeviceId = NewType("OtherDeviceId", str)
