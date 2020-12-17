from pydantic import BaseModel

from vccs.server.db import Type


class RequestFactor(BaseModel):
    H1: str
    credential_id: str
    type: Type
