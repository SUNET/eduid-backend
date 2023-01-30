from eduid.common.models.scim_base import EduidBaseModel

__author__ = "lundberg"


class TokenRequest(EduidBaseModel):
    data_owner: str
