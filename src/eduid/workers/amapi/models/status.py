__author__ = "masv"

from pydantic import BaseModel


class StatusResponse(BaseModel):
    status: str
    hostname: str
