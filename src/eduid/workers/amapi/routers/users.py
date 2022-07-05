from typing import Any, Dict, List, Optional

from fastapi import Response

from eduid.userdb import user
from eduid.common.fastapi.api_router import APIRouter
from eduid.workers.amapi.context_request import ContextRequest, ContextRequestRoute
from eduid.common.fastapi.exceptions import BadRequest, ErrorDetail, NotFound
from eduid.workers.amapi.models.user import UserUpdateEmailRequest, UserUpdateNameRequest, UserUpdateResponse
from eduid.workers.amapi.routers.utils.users import patch_user_email, patch_user_name

users_router = APIRouter(
    route_class=ContextRequestRoute,
    prefix='/Users',
    responses={
        400: {'description': 'Bad request', 'model': ErrorDetail},
        404: {'description': 'Not found', 'model': ErrorDetail},
        500: {'description': 'Internal server error', 'model': ErrorDetail},
    },
)


@users_router.patch('/{eppn}/name', response_model=UserUpdateResponse)
async def on_update_name(
    ctx: ContextRequest, resp: Response, req: UserUpdateNameRequest, eppn: Optional[str] = None
) -> None:
    if eppn is None:
        raise BadRequest(detail="Not implemented")
    # if check ctx.user.Allowed()
    ctx.context.logger.info(f'Update user {eppn} name')
    return patch_user_name(ctx=ctx, eppn=eppn, req=req)


@users_router.patch('/{eppn}/email', response_model=UserUpdateResponse)
async def on_update_email(
    ctx: ContextRequest, resp: Response, req: UserUpdateEmailRequest, eppn: Optional[str] = None
) -> None:
    if eppn is None:
        raise BadRequest(detail="Not implemented")
    ctx.context.logger.info(f'Update user {eppn} email')
    return patch_user_email(ctx=ctx, eppn=eppn, req=req)
