from pydantic import BaseModel

from eduid.vccs.server.db import CredType


class RequestFactor(BaseModel):
    """ Add/auth password """

    H1: str
    credential_id: str
    type: CredType


class RevokeFactor(BaseModel):
    """ Revoke a credential """

    credential_id: str
    reason: str
    reference: str
