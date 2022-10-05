from typing import Union

from deepdiff import DeepDiff

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.mail import MailAddressList
from eduid.userdb.phone import PhoneNumberList
from eduid.workers.amapi.context_request import ContextRequest
from eduid.common.fastapi.exceptions import BadRequest
from eduid.workers.amapi.models.user import (
    UserUpdateEmailRequest,
    UserUpdateNameRequest,
    UserUpdateLanguageRequest,
    UserUpdatePhoneRequest,
    UserUpdateResponse,
    UserUpdateTerminateRequest,
    UserUpdateMetaRequest,
)
from eduid.userdb.logs.element import (
    UserLogElement,
)


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

    if isinstance(data, UserUpdateMetaRequest):
        user_obj.meta = data.meta

    if isinstance(data, UserUpdateEmailRequest):
        if data is None:
            raise BadRequest(detail="mail_addresses can't be nil")
        user_obj.mail_addresses = MailAddressList.from_list(data.mail_addresses)

    if isinstance(data, UserUpdateLanguageRequest):
        if data is None:
            raise BadRequest(detail="language can't be nil")
        user_obj.language = data.language

    if isinstance(data, UserUpdatePhoneRequest):
        if data is None:
            raise BadRequest(detail="phone_numbers can't be nil")
        user_obj.phone_numbers = PhoneNumberList.from_list(data.phone_numbers)

    if isinstance(data, UserUpdateTerminateRequest):
        user_obj.terminated = utc_now()

    user_obj.meta.new_version()
    new_user_dict = user_obj.to_dict()

    diff = DeepDiff(old_user_dict, new_user_dict, ignore_order=True).to_json()

    audit_msg = UserLogElement(
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
