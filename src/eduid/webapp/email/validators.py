from marshmallow import ValidationError

from eduid.webapp.common.api.utils import get_user
from eduid.webapp.email.helpers import EmailMsg


def email_exists(email: str) -> None:
    user = get_user()
    user_emails = [e.email for e in user.mail_addresses.to_list()]
    if email not in user_emails:
        raise ValidationError(EmailMsg.missing.value)


def email_does_not_exist(email: str) -> None:
    user = get_user()
    user_emails = [e.email for e in user.mail_addresses.to_list()]
    if email in user_emails:
        raise ValidationError(EmailMsg.dupe.value)
