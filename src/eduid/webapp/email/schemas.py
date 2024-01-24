from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid.webapp.common.api.schemas.email import LowercaseEmail
from eduid.webapp.common.api.schemas.validators import validate_email
from eduid.webapp.email.validators import email_does_not_exist, email_exists

__author__ = "eperez"


class NoCSRFVerificationCodeSchema(EduidSchema):
    # Create the VerificationCodeSchema without forced CSRF token so it can be used for the GET verification view also
    code = fields.String(required=True)
    email = LowercaseEmail(required=True, validate=[validate_email, email_exists])


class VerificationCodeSchema(NoCSRFVerificationCodeSchema, CSRFRequestMixin):
    pass


class EmailSchema(EduidSchema, CSRFRequestMixin):
    email = LowercaseEmail(required=True, validate=validate_email)
    verified = fields.Boolean(attribute="verified")
    primary = fields.Boolean(attribute="primary")


class AddEmailSchema(EmailSchema):
    email = LowercaseEmail(required=True, validate=[validate_email, email_does_not_exist])


class ChangeEmailSchema(EduidSchema, CSRFRequestMixin):
    email = LowercaseEmail(required=True, validate=[validate_email, email_exists])


class EmailListPayload(EduidSchema, CSRFRequestMixin, CSRFResponseMixin):
    emails = fields.Nested(EmailSchema, many=True)


class EmailResponseSchema(FluxStandardAction):
    payload = fields.Nested(EmailListPayload)
