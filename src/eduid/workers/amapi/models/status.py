# -*- coding: utf-8 -*-
__author__ = "masv"

from pydantic import BaseModel


class StatusResponse(BaseModel):
    status: str
    hostname: str
