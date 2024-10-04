from typing import Any

from marshmallow import ValidationError, fields, validates

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid.webapp.common.api.schemas.identity import IdentitiesSchema
from eduid.webapp.common.api.schemas.password import PasswordSchema
from eduid.webapp.common.api.schemas.validators import validate_nin


class CredentialSchema(EduidSchema):
    key = fields.String(required=True)
    credential_type = fields.String(required=True)
    created_ts = fields.String(required=True)
    success_ts = fields.String(required=True)
    used_for_login = fields.Boolean(required=True, default=False)
    verified = fields.Boolean(required=True, default=False)
    description = fields.String(required=False)


class CredentialList(EduidSchema, CSRFResponseMixin):
    credentials = fields.Nested(CredentialSchema, many=True)


class SecurityResponseSchema(FluxStandardAction):
    payload = fields.Nested(CredentialList)


class ChpassResponseSchema(SecurityResponseSchema):
    class ChpassResponsePayload(CredentialList):
        next_url = fields.String(required=True)

    payload = fields.Nested(ChpassResponsePayload)


class ChangePasswordRequestSchema(EduidSchema, CSRFRequestMixin):
    old_password = fields.String(required=False)
    new_password = fields.String(required=True)


class RedirectResponseSchema(FluxStandardAction):
    class RedirectPayload(EduidSchema, CSRFResponseMixin):
        location = fields.String(required=True)

    payload = fields.Nested(RedirectPayload, many=False)


class SuggestedPasswordResponseSchema(FluxStandardAction):
    class SuggestedPasswordPayload(EduidSchema, CSRFResponseMixin):
        suggested_password = fields.String(required=True)

    payload = fields.Nested(SuggestedPasswordPayload, many=False)


# TODO: Remove this when frontend for new change password view exist
class ChangePasswordSchema(PasswordSchema):
    csrf_token = fields.String(required=True)
    old_password = fields.String(required=True)
    new_password = fields.String(required=True)
    authn_id = fields.String(required=False)

    @validates("new_password")
    def validate_custom_password(self, value: str, **kwargs: Any) -> None:
        # Set a new error message
        try:
            self.validate_password(value)
        except ValidationError:
            raise ValidationError("chpass.weak-pass")


class AccountTerminatedSchema(FluxStandardAction):
    pass


# webauthn schemas
class WebauthnOptionsResponseSchema(FluxStandardAction):
    class WebauthnOptionsResponsePayload(EduidSchema, CSRFResponseMixin):
        options = fields.String(required=True)

    payload = fields.Nested(WebauthnOptionsResponsePayload)


class WebauthnRegisterBeginSchema(EduidSchema, CSRFRequestMixin):
    authenticator = fields.String(required=True)


class WebauthnRegisterRequestSchema(EduidSchema, CSRFRequestMixin):
    credential_id = fields.String(required=True, data_key="credentialId")
    attestation_object = fields.String(required=True, data_key="attestationObject")
    client_data = fields.String(required=True, data_key="clientDataJSON")
    description = fields.String(required=True)


class RemoveWebauthnTokenRequestSchema(EduidSchema, CSRFRequestMixin):
    credential_key = fields.String(required=True)


class VerifyWithWebauthnTokenRequestSchema(EduidSchema):
    key_handle = fields.String(required=True, data_key="keyHandle")
    signature_data = fields.String(required=True, data_key="signatureData")
    client_data = fields.String(required=True, data_key="clientData")


class VerifyWithWebauthnTokenResponseSchema(FluxStandardAction):
    class Payload(CSRFResponseMixin):
        key_handle = fields.String(required=True, data_key="keyHandle")
        signature_data = fields.String(required=True, data_key="signatureData")
        client_data = fields.String(required=True, data_key="clientData")

    payload = fields.Nested(Payload)


# NIN schemas
class NINRequestSchema(EduidSchema, CSRFRequestMixin):
    nin = fields.String(required=True, validate=validate_nin)


class IdentityRequestSchema(EduidSchema, CSRFRequestMixin):
    identity_type = fields.String(required=True)


class IdentitiesResponseSchema(FluxStandardAction):
    class RemoveIdentityPayload(EduidSchema, CSRFResponseMixin):
        message = fields.String(required=False)
        identities = fields.Nested(IdentitiesSchema)

    payload = fields.Nested(RemoveIdentityPayload)


class UserUpdateResponseSchema(FluxStandardAction):
    class UserUpdatePayload(EduidSchema, CSRFRequestMixin):
        given_name = fields.String(attribute="givenName")
        surname = fields.String()

    payload = fields.Nested(UserUpdatePayload)


# follow same format of FIDO Alliance Metadata Service (MDS version 3) BLOB
class SecurityKeysResponseSchema(FluxStandardAction):
    next_update = fields.DateTime(required=True)
    entries = fields.List(fields.String())


class AuthnStatusRequestSchema(EduidSchema, CSRFRequestMixin):
    frontend_action = fields.String(required=True)
    credential_id = fields.String(required=False)


class AuthnStatusResponseSchema(FluxStandardAction):
    class AuthnStatusPayload(EduidSchema, CSRFRequestMixin):
        authn_status = fields.String(required=True)

    payload = fields.Nested(AuthnStatusPayload)
