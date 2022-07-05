from typing import List

from pydantic import BaseModel

__author__ = 'masv'


class SamplerResponse(BaseModel):
    eppns: List[str]


class SamplerRequest(BaseModel):
    sample_size: int
    exclude_process_id: str
