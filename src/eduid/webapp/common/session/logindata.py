from datetime import datetime

from pydantic import BaseModel

from eduid.userdb.element import ElementKey


class ExternalMfaData(BaseModel):
    """
    Data about a successful external authentication as a multi factor.
    """

    issuer: str
    authn_context: str
    timestamp: datetime
    credential_id: ElementKey | None = None
