from enum import StrEnum, unique

__author__ = "lundberg"


@unique
class SvipeIDAction(StrEnum):
    verify_identity = "verify-identity-action"
