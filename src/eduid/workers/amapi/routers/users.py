from eduid.common.fastapi.api_router import APIRouter
from eduid.common.fastapi.exceptions import ErrorDetail
from eduid.common.models.amapi_user import (
    UserUpdateEmailRequest,
    UserUpdateLanguageRequest,
    UserUpdateMetaCleanedRequest,
    UserUpdateNameRequest,
    UserUpdatePhoneRequest,
    UserUpdateResponse,
    UserUpdateTerminateRequest,
)
from eduid.workers.amapi.context_request import ContextRequest, ContextRequestRoute
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
async def on_put_name(req: ContextRequest, data: UserUpdateNameRequest, eppn: str):
    req.app.context.logger.info(f"Update user {eppn} name")
    return update_user(req=req, eppn=eppn, data=data)


@users_router.put("/{eppn}/email", response_model=UserUpdateResponse)
async def on_put_email(req: ContextRequest, data: UserUpdateEmailRequest, eppn: str):
    req.app.context.logger.info(f"Update user {eppn} email")
    return update_user(req=req, eppn=eppn, data=data)


@users_router.put("/{eppn}/language", response_model=UserUpdateResponse)
async def on_put_language(req: ContextRequest, data: UserUpdateLanguageRequest, eppn: str):
    req.app.context.logger.info(f"Update user {eppn} language")
    return update_user(req=req, eppn=eppn, data=data)


@users_router.put("/{eppn}/phone", response_model=UserUpdateResponse)
async def on_put_phone(req: ContextRequest, data: UserUpdatePhoneRequest, eppn: str):
    req.app.context.logger.info(f"Update user {eppn} phone")
    return update_user(req=req, eppn=eppn, data=data)


@users_router.put("/{eppn}/meta/cleaned", response_model=UserUpdateResponse)
async def on_put_meta_cleaned(req: ContextRequest, data: UserUpdateMetaCleanedRequest, eppn: str):
    req.app.context.logger.info(f"Update user {eppn} meta/cleaned")
    return update_user(req=req, eppn=eppn, data=data)


@users_router.put("/{eppn}/terminate", response_model=UserUpdateResponse)
async def on_terminate_user(req: ContextRequest, data: UserUpdateTerminateRequest, eppn: str):
    req.app.context.logger.info(f"Terminate user {eppn}")
    return update_user(req=req, eppn=eppn, data=data)
