from typing import Optional

from fastapi import APIRouter, Form, Request
from pydantic.main import BaseModel

add_creds_router = APIRouter()



class AddCredsRequest(BaseModel):
    request: Optional[str]

class AddCredsResponse(BaseModel):
    status: str

#class AddCredsForm(BaseModel):
#    request: str = Form(...)

@add_creds_router.post("/add_creds")
async def add_creds(req: Request, request: str = Form(...)):
    req.app.logger.info(f'Add credentials (using form): {request}')
    return {'status': 'TESTING'}
