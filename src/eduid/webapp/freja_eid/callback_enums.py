from enum import StrEnum, unique

__author__ = "lundberg"


@unique
class FrejaEIDAction(StrEnum):
    verify_identity = "verify-identity-action"
