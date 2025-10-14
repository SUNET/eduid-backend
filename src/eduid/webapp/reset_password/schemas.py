from typing import Any

from marshmallow import fields, pre_dump

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid.webapp.common.api.schemas.email import LowercaseEmail
from eduid.webapp.common.api.utils import time_left
from eduid.webapp.reset_password.app import current_reset_password_app as current_app


class ResetPasswordStatusResponse(FluxStandardAction):
    class StatusSchema(EduidSchema, CSRFResponseMixin):
        class State(EduidSchema):
            class EmailVerification(EduidSchema):
                address = fields.String(required=False)
                completed = fields.Boolean(required=True)
                sent_at = fields.DateTime(required=False)
                throttle_time_left = fields.Integer(required=False)
                throttle_time_max = fields.Integer(required=False)
                expires_time_left = fields.Integer(required=False)
                expires_time_max = fields.Integer(required=False)

            class Captcha(EduidSchema):
                completed = fields.Boolean(required=True)

            email = fields.Nested(EmailVerification, required=True)
            captcha = fields.Nested(Captcha, required=True)

        state = fields.Nested(State, required=True)

    payload = fields.Nested(StatusSchema)

    @pre_dump
    def throttle_delta_to_seconds(self, out_data: dict, **kwargs: Any) -> dict:
        if out_data["payload"].get("state", {}).get("email", {}).get("sent_at"):
            sent_at = out_data["payload"]["state"]["email"]["sent_at"]
            throttle_time_left = time_left(sent_at, current_app.conf.throttle_resend).total_seconds()
            if throttle_time_left > 0:
                out_data["payload"]["state"]["email"]["throttle_time_left"] = throttle_time_left
                out_data["payload"]["state"]["email"]["throttle_time_max"] = (
                    current_app.conf.throttle_resend.total_seconds()
                )
        return out_data

    @pre_dump
    def email_verification_timeout_delta_to_seconds(self, out_data: dict, **kwargs: Any) -> dict:
        if out_data["payload"].get("state", {}).get("email", {}).get("sent_at"):
            sent_at = out_data["payload"]["state"]["email"]["sent_at"]
            verification_time_left = time_left(sent_at, current_app.conf.email_code_timeout).total_seconds()
            if verification_time_left > 0:
                out_data["payload"]["state"]["email"]["expires_time_left"] = verification_time_left
                out_data["payload"]["state"]["email"]["expires_time_max"] = (
                    current_app.conf.email_code_timeout.total_seconds()
                )
        return out_data


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


class SuggestedPasswordResponseSchema(FluxStandardAction):
    class SuggestedPasswordPayload(EduidSchema, CSRFResponseMixin):
        suggested_password = fields.String(required=True)

    payload = fields.Nested(SuggestedPasswordPayload, many=False)


class NewPasswordSecurePhoneRequestSchema(EduidSchema, CSRFRequestMixin):
    email_code = fields.String(required=True)
    password = fields.String(required=True)
    phone_code = fields.String(required=True)


class NewPasswordRequestSchema(EduidSchema, CSRFRequestMixin):
    email_code = fields.String(required=True)
    password = fields.String(required=True)


class NewPasswordSecurityKeyRequestSchema(NewPasswordRequestSchema):
    webauthn_response = fields.Dict(keys=fields.Str(), load_default=None, required=False)
