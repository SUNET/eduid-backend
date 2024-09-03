from enum import Enum, unique

__author__ = "lundberg"


@unique
class FrejaEIDAction(str, Enum):
    verify_identity = "verify-identity-action"
