from typing import Union

from deepdiff import DeepDiff

from eduid.common.fastapi.exceptions import BadRequest
from eduid.common.misc.timeutil import utc_now
from eduid.userdb.logs.element import UserChangeLogElement
from eduid.userdb.mail import MailAddressList
from eduid.userdb.phone import PhoneNumberList
from eduid.workers.amapi.context_request import ContextRequest
from eduid.workers.amapi.models.user import (
    UserUpdateEmailRequest,
    UserUpdateLanguageRequest,
    UserUpdateMetaRequest,
    UserUpdateNameRequest,
    UserUpdatePhoneRequest,
    UserUpdateResponse,
    UserUpdateTerminateRequest,
)


def create_user(req: ContextRequest, eppn: str, data: CreateUserRequest) -> UserCreateResponse:
    # mailAliases
    # eppn
    # passwords
    # tou
    pass


def update_user(
    req: ContextRequest,
    eppn: str,
    data: Union[
        UserUpdateEmailRequest,
        UserUpdateNameRequest,
        UserUpdateMetaRequest,
        UserUpdateLanguageRequest,
        UserUpdatePhoneRequest,
        UserUpdateTerminateRequest,
    ],
) -> UserUpdateResponse:
    """General function for updating a user object"""

    user_obj = req.app.db.get_user_by_eppn(eppn=eppn)
    if user_obj is None:
        raise BadRequest(detail=f"Can't find {eppn} in database")

    old_user_dict = user_obj.to_dict()

    old_version = user_obj.meta.version

    if isinstance(data, UserUpdateNameRequest):
        user_obj.surname = data.surname
        user_obj.given_name = data.given_name
        user_obj.display_name = data.display_name

    elif isinstance(data, UserUpdateMetaRequest):
        user_obj.meta = data.meta

    elif isinstance(data, UserUpdateEmailRequest):
        user_obj.mail_addresses = MailAddressList(elements=data.mail_addresses)

    elif isinstance(data, UserUpdateLanguageRequest):
        user_obj.language = data.language

    elif isinstance(data, UserUpdatePhoneRequest):
        user_obj.phone_numbers = PhoneNumberList(elements=data.phone_numbers)

    elif isinstance(data, UserUpdateTerminateRequest):
        user_obj.terminated = utc_now()

    user_obj.meta.new_version()
    new_user_dict = user_obj.to_dict()

    diff = DeepDiff(old_user_dict, new_user_dict, ignore_order=True).to_json()

    audit_msg = UserChangeLogElement(
        created_by="am_api",
        eppn=eppn,
        diff=diff,
        reason=data.reason,
        source=data.source,
    )

    if req.app.audit_logger.save(audit_msg):
        req.app.logger.info(f"Add audit log record for {eppn}")
        req.app.db.replace_user(
            obj_id=user_obj.user_id,
            eppn=user_obj.eppn,
            old_version=old_version,
            update_obj=new_user_dict,
        )

    return UserUpdateResponse(
        status=True,
        diff=diff,
    )
