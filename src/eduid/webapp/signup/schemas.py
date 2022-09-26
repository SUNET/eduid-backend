# -*- coding: utf-8 -*-

from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid.webapp.common.api.schemas.email import LowercaseEmail
from eduid.webapp.common.api.schemas.validators import validate_email

__author__ = 'lundberg'


class SignupStatusResponse(FluxStandardAction):
    class StatusSchema(EduidSchema, CSRFResponseMixin):
        class EmailVerification(EduidSchema):
            email = fields.String(required=False)
            verified = fields.Boolean(required=True)
            sent_ts = fields.DateTime(required=True)

        class Invite(EduidSchema):
            initiated_signup = fields.Boolean(required=True)
            code = fields.String(required=True)
            finish_url = fields.String(required=True)
            completed = fields.Boolean(required=True)

        email_verification = fields.Nested(EmailVerification, required=True)
        invite = fields.Nested(Invite, required=True)
        tou_accepted = fields.Boolean(required=True)
        captcha_completed = fields.Boolean(required=True)
        credential_added = fields.Boolean(required=True)
        user_created = fields.Boolean(required=True)

    payload = fields.Nested(StatusSchema)


class AcceptTouRequest(EduidSchema, CSRFRequestMixin):
    tou_accepted = fields.Boolean(required=True)
    tou_version = fields.String(required=True)


class CaptchaResponse(FluxStandardAction):
    class CaptchaResponseSchema(EduidSchema, CSRFResponseMixin):
        captcha_img = fields.String(required=False)
        captcha_audio = fields.String(required=False)
        recaptcha = fields.Boolean(default=True)

    payload = fields.Nested(CaptchaResponseSchema)


class CaptchaCompleteRequest(EduidSchema, CSRFRequestMixin):
    recaptcha_response = fields.String(required=True)


class EmailSchema(EduidSchema, CSRFRequestMixin):
    email = LowercaseEmail(required=True, validate=[validate_email])


class VerifyEmailSchema(EmailSchema):
    verification_code = fields.String(required=True)


class InviteCodeRequest(EduidSchema, CSRFRequestMixin):
    invite_code = fields.String(required=True)


class InviteDataResponse(FluxStandardAction):
    class InviteSchema(EduidSchema, CSRFResponseMixin):
        invite_type = fields.String(required=True)
        inviter_name = fields.String(required=True)
        email = fields.String(required=True)
        preferred_language = fields.String(required=True)
        expires_at = fields.DateTime(required=True)
        given_name = fields.String(required=False)
        surname = fields.String(required=False)
        finish_url = fields.String(required=False)

    payload = fields.Nested(InviteSchema)


class InviteCompletedResponse(FluxStandardAction):
    class InviteCompletedSchema(EduidSchema, CSRFResponseMixin):
        finish_url = fields.String(required=False)

    payload = fields.Nested(InviteCompletedSchema)
