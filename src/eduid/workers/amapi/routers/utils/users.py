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
    UserUpdateNameRequest,
    UserUpdatePhoneRequest,
    UserUpdateResponse,
    UserUpdateTerminateRequest,
)


def update_user(
    req: ContextRequest,
    eppn: str,
    data: Union[
        UserUpdateEmailRequest,
        UserUpdateNameRequest,
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

    if isinstance(data, UserUpdateNameRequest):
        user_obj.surname = data.surname
        user_obj.given_name = data.given_name
        user_obj.display_name = data.display_name

    elif isinstance(data, UserUpdateEmailRequest):
        mails = [mail.to_dict() for mail in data.mail_addresses]
        req.app.db.unverify_mail_aliases(user_id=user_obj.user_id, mail_aliases=mails)

        user_obj.mail_addresses = MailAddressList(elements=data.mail_addresses)

    elif isinstance(data, UserUpdateLanguageRequest):
        user_obj.language = data.language

    elif isinstance(data, UserUpdatePhoneRequest):
        phones = [phone.to_dict() for phone in data.phone_numbers]
        req.app.db.unverify_phones(user_id=user_obj.user_id, phones=phones)

        user_obj.phone_numbers = PhoneNumberList(elements=data.phone_numbers)

    elif isinstance(data, UserUpdateTerminateRequest):
        user_obj.terminated = utc_now()

    user_update_response = UserUpdateResponse()

    user_save_result = req.app.db.save(user=user_obj)
    if user_save_result.success:
        if user_save_result.user is not None:
            diff = DeepDiff(old_user_dict, user_save_result.user.to_dict(), ignore_order=True).to_json()
            user_update_response.diff = diff
            audit_msg = UserChangeLogElement(
                created_by="am_api",
                eppn=eppn,
                log_element_id=None,
                diff=diff,
                reason=data.reason,
                source=data.source,
            )
            if req.app.audit_logger.save(audit_msg):
                req.app.logger.info(f"Add audit log record for {eppn}")
            user_update_response.status = True

    user_update_response.status = False
    return user_update_response
