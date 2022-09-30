# -*- coding: utf-8 -*-

from marshmallow import fields, pre_dump

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid.webapp.common.api.schemas.email import LowercaseEmail
from eduid.webapp.common.api.schemas.validators import validate_email
from eduid.webapp.common.api.utils import throttle_time_left
from eduid.webapp.signup.app import current_signup_app as current_app

__author__ = 'lundberg'


class SignupStatusResponse(FluxStandardAction):
    class StatusSchema(EduidSchema, CSRFResponseMixin):
        class EmailVerification(EduidSchema):
            email = fields.String(required=False)
            verified = fields.Boolean(required=True)
            sent_at = fields.DateTime(required=False)
            throttle_time_left = fields.Integer(required=False)
            throttle_time_max = fields.Integer(required=False)
            bad_attempts = fields.Integer(required=False)
            bad_attempts_max = fields.Integer(required=False)

        class Invite(EduidSchema):
            initiated_signup = fields.Boolean(required=True)
            code = fields.String(required=False)
            finish_url = fields.String(required=False)
            completed = fields.Boolean(required=True)

        email_verification = fields.Nested(EmailVerification, required=True)
        invite = fields.Nested(Invite, required=True)
        tou_accepted = fields.Boolean(required=True)
        captcha_completed = fields.Boolean(required=True)
        credential_added = fields.Boolean(required=True)
        user_created = fields.Boolean(required=True)

    payload = fields.Nested(StatusSchema)

    @pre_dump
    def throttle_delta_to_seconds(self, out_data, **kwargs):
        if out_data['payload'].get('email_verification', {}).get('sent_at'):
            sent_at = out_data['payload']['email_verification']['sent_at']
            time_left = throttle_time_left(sent_at, current_app.conf.throttle_resend).total_seconds()
            if time_left > 0:
                out_data['payload']['email_verification']['throttle_time_left'] = time_left
                out_data['payload']['email_verification'][
                    'throttle_time_max'
                ] = current_app.conf.throttle_resend.total_seconds()
        return out_data

    @pre_dump
    def bad_attempts_max(self, out_data, **kwargs):
        if out_data['payload'].get('email_verification'):
            out_data['payload']['email_verification'][
                'bad_attempts_max'
            ] = current_app.conf.email_verification_max_bad_attempts
        return out_data


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


class VerifyEmailRequest(EduidSchema, CSRFRequestMixin):
    verification_code = fields.String(required=True)


class CreateUserRequest(EduidSchema, CSRFRequestMixin):
    use_password = fields.Boolean(required=True)
    use_webauthn = fields.Boolean(required=True)


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
