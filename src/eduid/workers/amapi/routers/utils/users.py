from typing import Any, Dict, List, Optional, Sequence, Tuple

from bson import ObjectId

from eduid.workers.amapi.context_request import ContextRequest
from eduid.common.fastapi.exceptions import BadRequest
from eduid.workers.amapi.models.user import UserUpdateEmailRequest, UserUpdateNameRequest


def patch_user_name(ctx: ContextRequest, eppn: str, req: UserUpdateNameRequest) -> None:
    """Update user name information"""

    user = ctx.app.db.get_user_by_eppn(eppn=eppn)
    if user is None:
        raise BadRequest(detail='User can not be None')

    try:
        ctx.app.db.update_user(obj_id=user.user_id, operations=req.operation())
    except ConnectionError as e:
        ctx.app.logger.error(f'update_attributes_keep_result connection error: {e}', exc_info=True)
        # self.retry(default_retry_delay=1, max_retries=3, exc=e)


def patch_user_email(ctx: ContextRequest, eppn: str, req: UserUpdateEmailRequest) -> None:
    """Update user name information"""
