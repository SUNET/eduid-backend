from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid.webapp.common.api.schemas.email import LowercaseEmail

__author__ = "eperez"


class ResetPasswordEmailRequestSchema(EduidSchema, CSRFRequestMixin):
    email = LowercaseEmail(required=True)


class ResetPasswordEmailCodeRequestSchema(EduidSchema, CSRFRequestMixin):
    email_code = fields.String(required=True)


class ResetPasswordCaptchaResponseSchema(FluxStandardAction):
    class ResetPasswordCaptchaResponsePayload(EduidSchema, CSRFResponseMixin):
        captcha_completed = fields.Boolean(required=True, dump_default=False)

    payload = fields.Nested(ResetPasswordCaptchaResponsePayload)


class ResetPasswordEmailResponseSchema(FluxStandardAction):
    class ResetPasswordEmailResponsePayload(EduidSchema, CSRFResponseMixin):
        email = LowercaseEmail(required=True)
        email_code_timeout = fields.Int(required=True)
        throttled_seconds = fields.Int(required=True)
        throttled_max = fields.Int(required=True)

    payload = fields.Nested(ResetPasswordEmailResponsePayload)


class ResetPasswordResponseSchema(FluxStandardAction):
    class ResetPasswordResponsePayload(EduidSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(ResetPasswordResponsePayload)


class ResetPasswordVerifyEmailResponseSchema(FluxStandardAction):
    class ResetPasswordVerifyEmailResponsePayload(EduidSchema, CSRFResponseMixin):
        suggested_password = fields.String(required=True)
        email_code = fields.String(required=True)
        email_address = fields.String(required=True)
        extra_security = fields.Dict(required=True)
        success = fields.Bool(required=True)
        zxcvbn_terms = fields.List(required=True, cls_or_instance=fields.String)

    payload = fields.Nested(ResetPasswordVerifyEmailResponsePayload)


class ResetPasswordExtraSecPhoneSchema(EduidSchema, CSRFRequestMixin):
    email_code = fields.String(required=True)
    phone_index = fields.Integer(required=True)


class ResetPasswordWithCodeSchema(EduidSchema, CSRFRequestMixin):
    email_code = fields.String(required=True)
    password = fields.String(required=True)


class ResetPasswordWithPhoneCodeSchema(ResetPasswordWithCodeSchema):
    phone_code = fields.String(required=True)


class ResetPasswordWithSecTokenSchema(ResetPasswordWithCodeSchema):
    authenticator_data = fields.String(required=False, data_key="authenticatorData")
    client_data_json = fields.String(required=False, data_key="clientDataJSON")
    credential_id = fields.String(required=False, data_key="credentialId")
    signature = fields.String(required=True)


class SuggestedPasswordResponseSchema(FluxStandardAction):
    class SuggestedPasswordPayload(EduidSchema, CSRFResponseMixin):
        suggested_password = fields.String(required=True)

    payload = fields.Nested(SuggestedPasswordPayload, many=False)


class NewPasswordSecurePhoneRequestSchema(EduidSchema, CSRFRequestMixin):
    email_code = fields.String(required=True)
    password = fields.String(required=True)
    phone_code = fields.String(required=True)


class NewPasswordSecureTokenRequestSchema(EduidSchema, CSRFRequestMixin):
    email_code = fields.String(required=True)
    password = fields.String(required=True)
    token_response = fields.String(required=False, data_key="tokenResponse")
    authenticator_data = fields.String(required=False, data_key="authenticatorData")
    client_data_json = fields.String(required=False, data_key="clientDataJSON")
    credential_id = fields.String(required=False, data_key="credentialId")
    signature = fields.String(required=False)
