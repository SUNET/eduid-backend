from typing import Optional

from eduid.common.fastapi.api_router import APIRouter
from eduid.common.fastapi.exceptions import BadRequest, ErrorDetail
from eduid.workers.amapi.context_request import ContextRequest, ContextRequestRoute
from eduid.workers.amapi.models.user import (
    UserUpdateEmailRequest,
    UserUpdateLanguageRequest,
    UserUpdateMetaRequest,
    UserUpdateNameRequest,
    UserUpdatePhoneRequest,
    UserUpdateResponse,
    UserUpdateTerminateRequest,
)
from eduid.workers.amapi.routers.utils.users import update_user

__author__ = "masv"

users_router = APIRouter(
    route_class=ContextRequestRoute,
    prefix="/users",
    responses={
        400: {"description": "Bad request", "model": ErrorDetail},
        404: {"description": "Not found", "model": ErrorDetail},
        500: {"description": "Internal server error", "model": ErrorDetail},
    },
)


@users_router.put("/{eppn}/name", response_model=UserUpdateResponse)
async def on_put_name(req: ContextRequest, data: UserUpdateNameRequest, eppn: Optional[str] = None):
    if eppn is None or data.source is None or data.reason is None:
        raise BadRequest(detail="Not implemented")
    req.app.logger.info(f"Update user {eppn} name")
    return update_user(req=req, eppn=eppn, data=data)


@users_router.put("/eppn/meta", response_model=UserUpdateResponse)
async def on_put_meta(req: ContextRequest, data: UserUpdateMetaRequest, eppn: Optional[str] = None):
    if eppn is None or data.source is None or data.reason is None:
        raise BadRequest(detail="Not implemented")
    req.app.logger.info(f"Update user {eppn} meta")
    return update_user(req=req, eppn=eppn, data=data)


@users_router.put("/{eppn}/email", response_model=UserUpdateResponse)
async def on_put_email(req: ContextRequest, data: UserUpdateEmailRequest, eppn: Optional[str] = None):
    if eppn is None or data.source is None or data.reason is None:
        raise BadRequest(detail="Not implemented")
    req.app.logger.info(f"Update user {eppn} email")
    return update_user(req=req, eppn=eppn, data=data)


@users_router.put("/{eppn}/language", response_model=UserUpdateResponse)
async def on_put_language(req: ContextRequest, data: UserUpdateLanguageRequest, eppn: Optional[str] = None):
    if eppn is None or data.source is None or data.reason is None:
        raise BadRequest(detail="Not implemented")
    req.app.logger.info(f"Update user {eppn} language")
    return update_user(req=req, eppn=eppn, data=data)


@users_router.put("/{eppn}/phone", response_model=UserUpdateResponse)
async def on_put_phone(req: ContextRequest, data: UserUpdatePhoneRequest, eppn: Optional[str] = None):
    if eppn is None or data.source is None or data.reason is None:
        raise BadRequest(detail="Not implemented")
    req.app.logger.info(f"Update user {eppn} phone")
    return update_user(req=req, eppn=eppn, data=data)


@users_router.delete("/{eppn}", response_model=UserUpdateTerminateRequest)
async def on_terminate_user(req: ContextRequest, data: UserUpdateTerminateRequest, eppn: Optional[str] = None):
    if eppn is None or data.source is None or data.reason is None:
        raise BadRequest(detail="Not implemented")
    req.app.logger.info(f"Terminate user {eppn} email")
    return update_user(req=req, eppn=eppn, data=data)
