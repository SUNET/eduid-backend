from deepdiff import DeepDiff

from eduid.common.misc.timeutil import utc_now
from eduid.common.models.amapi_user import (
    UserUpdateEmailRequest,
    UserUpdateLanguageRequest,
    UserUpdateMetaCleanedRequest,
    UserUpdateNameRequest,
    UserUpdatePhoneRequest,
    UserUpdateResponse,
    UserUpdateTerminateRequest,
)
from eduid.userdb.logs.element import UserChangeLogElement
from eduid.userdb.mail import MailAddressList
from eduid.userdb.phone import PhoneNumberList
from eduid.workers.amapi.context_request import ContextRequest


def update_user(
    req: ContextRequest,
    eppn: str,
    data: UserUpdateEmailRequest
    | UserUpdateNameRequest
    | UserUpdateLanguageRequest
    | UserUpdatePhoneRequest
    | UserUpdateMetaCleanedRequest
    | UserUpdateTerminateRequest,
) -> UserUpdateResponse:
    """General function for updating a user object"""
    user_obj = req.app.context.db.get_user_by_eppn(eppn=eppn)

    old_user_dict = user_obj.to_dict()

    if isinstance(data, UserUpdateNameRequest):
        user_obj.surname = data.surname
        user_obj.given_name = data.given_name
        user_obj.chosen_given_name = data.chosen_given_name
        user_obj.legal_name = data.legal_name

    elif isinstance(data, UserUpdateEmailRequest):
        mails = [mail.to_dict() for mail in data.mail_addresses]
        req.app.context.db.unverify_mail_aliases(user_id=user_obj.user_id, mail_aliases=mails)

        user_obj.mail_addresses = MailAddressList(elements=data.mail_addresses)

    elif isinstance(data, UserUpdateLanguageRequest):
        user_obj.language = data.language

    elif isinstance(data, UserUpdatePhoneRequest):
        phones = [phone.to_dict() for phone in data.phone_numbers]
        req.app.context.db.unverify_phones(user_id=user_obj.user_id, phones=phones)

        user_obj.phone_numbers = PhoneNumberList(elements=data.phone_numbers)

    elif isinstance(data, UserUpdateMetaCleanedRequest):
        user_obj.meta.cleaned.update({data.type: data.ts})

    elif isinstance(data, UserUpdateTerminateRequest):
        user_obj.terminated = utc_now()

    diff = None

    user_save_result = req.app.context.db.save(user=user_obj)
    if user_save_result.success:
        diff = DeepDiff(
            old_user_dict,
            user_obj.to_dict(),
            ignore_order=True,
            exclude_paths=["root['meta']['modified_ts']", "root['modified_ts']"],  # we do not care about these entries.
        ).to_json()
        audit_msg = UserChangeLogElement(
            created_by="amapi",
            eppn=eppn,
            log_element_id=None,
            diff=diff,
            reason=data.reason,
            source=data.source,
        )
        if req.app.context.audit_logger.save(audit_msg):
            req.app.context.logger.info(f"Add audit log record for {eppn}")

    return UserUpdateResponse(status=user_save_result.success, diff=diff)
