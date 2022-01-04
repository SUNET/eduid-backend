"""
Some data structures that causes import loops if they are defined in other_device.py.
"""
from enum import Enum
from typing import NewType


class OtherDeviceState(str, Enum):
    NEW = 'NEW'
    IN_PROGRESS = 'IN_PROGRESS'
    FINISHED = 'FINISHED'
    ABORTED = 'ABORTED'


OtherDeviceId = NewType('OtherDeviceId', str)
