from typing import Any

from marshmallow import fields, pre_dump

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid.webapp.common.api.schemas.email import LowercaseEmail
from eduid.webapp.common.api.schemas.validators import validate_email
from eduid.webapp.common.api.utils import time_left
from eduid.webapp.common.session import session
from eduid.webapp.signup.app import current_signup_app as current_app

__author__ = "lundberg"


class SignupStatusResponse(FluxStandardAction):
    class StatusSchema(EduidSchema, CSRFResponseMixin):
        class State(EduidSchema):
            class Name(EduidSchema):
                given_name = fields.String(required=False)
                surname = fields.String(required=False)

            class EmailVerification(EduidSchema):
                address = fields.String(required=False)
                completed = fields.Boolean(required=True)
                sent_at = fields.DateTime(required=False)
                throttle_time_left = fields.Integer(required=False)
                throttle_time_max = fields.Integer(required=False)
                expires_time_left = fields.Integer(required=False)
                expires_time_max = fields.Integer(required=False)
                bad_attempts = fields.Integer(required=False)
                bad_attempts_max = fields.Integer(required=False)

            class Invite(EduidSchema):
                initiated_signup = fields.Boolean(required=True)
                code = fields.String(required=False)
                finish_url = fields.String(required=False)
                completed = fields.Boolean(required=True)

            class Tou(EduidSchema):
                completed = fields.Boolean(required=True)
                version = fields.String(required=True)

            class Captcha(EduidSchema):
                completed = fields.Boolean(required=True)

            class Credentials(EduidSchema):
                completed = fields.Boolean(required=True)
                generated_password = fields.String(required=True, dump_default=None)
                custom_password = fields.Boolean(required=True, dump_default=False)
                webauthn_registered = fields.Boolean(required=True, dump_default=False)
                webauthn_is_discoverable = fields.Boolean(required=True, dump_default=False)
                webauthn_description = fields.String(required=True, dump_default=None)

            class ExternalMfa(EduidSchema):
                completed = fields.Boolean(required=True)
                app_name = fields.String(required=True, dump_default=None)
                given_name = fields.String(required=True, dump_default=None)
                surname = fields.String(required=True, dump_default=None)
                date_of_birth = fields.Date(required=True, dump_default=None)
                masked_nin = fields.String(required=True, dump_default=None)
                eidas_country = fields.String(required=True, dump_default=None)

            already_signed_up = fields.Boolean(required=True)
            name = fields.Nested(Name, required=True)
            email = fields.Nested(EmailVerification, required=True)
            invite = fields.Nested(Invite, required=True)
            tou = fields.Nested(Tou, required=True)
            captcha = fields.Nested(Captcha, required=True)
            credentials = fields.Nested(Credentials, required=True)
            external_mfa = fields.Nested(ExternalMfa, required=True)
            user_created = fields.Boolean(required=True)
            idp_request_ref = fields.String(required=False, load_default=None)

        state = fields.Nested(State, required=True)

    payload = fields.Nested(StatusSchema)

    @pre_dump
    def set_already_signed_up(self, data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        if data["payload"].get("state"):
            data["payload"]["state"]["already_signed_up"] = bool(session.common.eppn)
        return data

    @pre_dump
    def set_tou_version(self, data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        if data["payload"].get("state", {}).get("tou") and data["payload"]["state"]["tou"].get("version") is None:
            data["payload"]["state"]["tou"]["version"] = current_app.conf.tou_version
        return data

    @pre_dump
    def throttle_delta_to_seconds(self, out_data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
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
    def email_verification_timeout_delta_to_seconds(self, out_data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        if out_data["payload"].get("state", {}).get("email", {}).get("sent_at"):
            sent_at = out_data["payload"]["state"]["email"]["sent_at"]
            verification_time_left = time_left(sent_at, current_app.conf.email_verification_timeout).total_seconds()
            if verification_time_left > 0:
                out_data["payload"]["state"]["email"]["expires_time_left"] = verification_time_left
                out_data["payload"]["state"]["email"]["expires_time_max"] = (
                    current_app.conf.email_verification_timeout.total_seconds()
                )
        return out_data

    @pre_dump
    def bad_attempts_max(self, out_data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        if out_data["payload"].get("state", {}).get("email"):
            out_data["payload"]["state"]["email"]["bad_attempts_max"] = (
                current_app.conf.email_verification_max_bad_attempts
            )
        return out_data

    @pre_dump
    def set_webauthn_registered(self, out_data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        if out_data["payload"].get("state", {}).get("credentials"):
            credentials = out_data["payload"]["state"]["credentials"]
            webauthn = credentials.get("webauthn")
            credentials["webauthn_registered"] = bool(webauthn)
            credentials["webauthn_is_discoverable"] = bool(webauthn and webauthn.get("is_discoverable"))
            credentials["webauthn_description"] = webauthn.get("description") if webauthn else None
        return out_data

    @pre_dump
    def set_external_mfa(self, out_data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        state = out_data.get("payload", {}).get("state")
        if state is None:
            return out_data
        ext = state.get("external_mfa")
        if not ext:
            state["external_mfa"] = {
                "completed": False,
                "app_name": None,
                "given_name": None,
                "surname": None,
                "date_of_birth": None,
                "masked_nin": None,
                "eidas_country": None,
            }
            return out_data
        nin = ext.get("nin")
        masked = None
        nin_min_len = 8
        if nin and len(nin) >= nin_min_len:
            masked = f"{nin[:6]}**-****"
        state["external_mfa"] = {
            "completed": True,
            "app_name": ext.get("app_name"),
            "given_name": ext.get("given_name"),
            "surname": ext.get("surname"),
            "date_of_birth": ext.get("date_of_birth"),
            "masked_nin": masked,
            "eidas_country": ext.get("country_code"),
        }
        return out_data


class AcceptTouRequest(EduidSchema, CSRFRequestMixin):
    tou_accepted = fields.Boolean(required=True)
    tou_version = fields.String(required=True)


class NameAndEmailSchema(EduidSchema, CSRFRequestMixin):
    given_name = fields.String(required=True)
    surname = fields.String(required=True)
    email = LowercaseEmail(required=True, validate=[validate_email])


class VerifyEmailRequest(EduidSchema, CSRFRequestMixin):
    verification_code = fields.String(required=True)


class CreateUserRequest(EduidSchema, CSRFRequestMixin):
    use_suggested_password = fields.Boolean(required=True)
    custom_password = fields.String(required=False)
    use_webauthn = fields.Boolean(required=True)


class InviteCodeRequest(EduidSchema, CSRFRequestMixin):
    invite_code = fields.String(required=True)


class InviteDataResponse(FluxStandardAction):
    class InviteSchema(EduidSchema, CSRFResponseMixin):
        class User(EduidSchema):
            given_name = fields.String(required=False)
            surname = fields.String(required=False)
            email = LowercaseEmail(required=False)

        is_logged_in = fields.Boolean(required=True)
        user = fields.Nested(User, required=False)
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


class WebauthnRegisterBeginRequest(EduidSchema, CSRFRequestMixin):
    authenticator = fields.String(required=True)


class WebauthnRegisterCompleteRequest(EduidSchema, CSRFRequestMixin):
    response = fields.Dict(required=True)
    description = fields.String(required=True)
    client_extension_results = fields.Dict(required=False, data_key="clientExtensionResults")


class ReturnToAuthRequest(EduidSchema, CSRFRequestMixin):
    ref = fields.String(required=True)


class ExternalMfaRegisterRequest(EduidSchema, CSRFRequestMixin):
    app_name = fields.String(required=True)
    authn_id = fields.String(required=True)
