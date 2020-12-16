import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Form, Request
from pydantic.main import BaseModel

add_creds_router = APIRouter()


class AddCredsRequestV1(BaseModel):
    factors: List[Dict[str, str]]
    user_id: str
    version: int


class AddCredsResponseV1(BaseModel):
    success: bool
    version: int


class AddCredsFormResponse(BaseModel):
    """ Extra wrapping class to handle legacy requests sent as form data """

    add_creds_response: AddCredsResponseV1


@add_creds_router.post("/add_creds", response_model=AddCredsFormResponse)
async def add_creds_legacy(req: Request, request: str = Form(...)) -> AddCredsFormResponse:
    req.app.logger.debug(f'Add credentials (using form): {request}')

    class AddCredsInnerRequest(BaseModel):
        """ Requests all the way down. """

        add_creds: AddCredsRequestV1

    data = json.loads(request)
    inner = AddCredsInnerRequest(**data)

    req.app.logger.debug(f'Inner request: {repr(inner)}')
    inner_response = await add_creds(req, inner.add_creds)
    response = AddCredsFormResponse(add_creds_response=inner_response)
    req.app.logger.debug(f'Add creds (form) response: {repr(response)}')
    return response


@add_creds_router.post("/v2/add_creds", response_model=AddCredsFormResponse)
async def add_creds(req: Request, request: AddCredsRequestV1) -> AddCredsResponseV1:
    response = AddCredsResponseV1(version=1, success=True)
    req.app.logger.debug(f'Add creds response: {repr(response)}')
    return response
