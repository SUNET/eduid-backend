from typing import Any

from marshmallow import fields, pre_load

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid.webapp.phone.validators import normalize_to_e_164, validate_format_phone, validate_phone

__author__ = "eperez"


class VerificationCodeSchema(EduidSchema, CSRFRequestMixin):
    code = fields.String(required=True)
    number = fields.String(required=True, validate=validate_format_phone)


class PhoneSchema(EduidSchema, CSRFRequestMixin):
    number = fields.String(required=True, validate=validate_phone)
    verified = fields.Boolean(attribute="verified")
    primary = fields.Boolean(attribute="primary")

    @pre_load
    def normalize_phone_number(self, in_data: dict, **kwargs: Any) -> dict:
        if in_data.get("number"):
            in_data["number"] = normalize_to_e_164(in_data["number"])
        return in_data


class PhoneListPayload(EduidSchema, CSRFRequestMixin, CSRFResponseMixin):
    phones = fields.Nested(PhoneSchema, many=True)


class PhoneResponseSchema(FluxStandardAction):
    payload = fields.Nested(PhoneListPayload)

    class Captcha(EduidSchema):
        completed = fields.Boolean(required=True)


class SimplePhoneSchema(EduidSchema, CSRFRequestMixin):
    number = fields.String(required=True)


class CaptchaResponse(FluxStandardAction):
    class CaptchaResponseSchema(EduidSchema, CSRFResponseMixin):
        captcha_img = fields.String(required=False)
        captcha_audio = fields.String(required=False)

    payload = fields.Nested(CaptchaResponseSchema)


class CaptchaCompleteRequest(EduidSchema, CSRFRequestMixin):
    internal_response = fields.String(required=False)
