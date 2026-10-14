from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid.webapp.common.api.schemas.identity import IdentitiesSchema
from eduid.webapp.common.api.schemas.validators import validate_nin


class CredentialSchema(EduidSchema):
    key = fields.String(required=True)
    credential_type = fields.String(required=True)
    created_ts = fields.String(required=True)
    success_ts = fields.String(required=True)
    used_for_login = fields.Boolean(required=True)
    verified = fields.Boolean(required=True)
    description = fields.String(required=False)
    authenticator = fields.String(required=False)
    mfa_approved = fields.Boolean(required=False)


class CredentialList(EduidSchema, CSRFResponseMixin):
    credentials = fields.Nested(CredentialSchema, many=True)


class SecurityResponseSchema(FluxStandardAction):
    payload = fields.Nested(CredentialList)


class ChangePasswordRequestSchema(EduidSchema, CSRFRequestMixin):
    old_password = fields.String(required=False)
    new_password = fields.String(required=True)


class SuggestedPasswordResponseSchema(FluxStandardAction):
    class SuggestedPasswordPayload(EduidSchema, CSRFResponseMixin):
        suggested_password = fields.String(required=True)

    payload = fields.Nested(SuggestedPasswordPayload, many=False)


class AccountTerminatedSchema(FluxStandardAction):
    pass


class WebauthnRegisterBeginSchema(EduidSchema, CSRFRequestMixin):
    authenticator = fields.String(required=True)


class WebauthnRegisterRequestSchema(EduidSchema, CSRFRequestMixin):
    response = fields.Dict(required=True)
    description = fields.String(required=True)
    client_extension_results = fields.Dict(required=False, data_key="clientExtensionResults")


class RemoveWebauthnTokenRequestSchema(EduidSchema, CSRFRequestMixin):
    credential_key = fields.String(required=True)


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


class AuthnResponseSchema(FluxStandardAction):
    class AuthnPayload(EduidSchema, CSRFRequestMixin):
        asserted_authn_ctx = fields.String(required=True)
        authn_instant = fields.DateTime(required=True)
        consumed = fields.Boolean(required=True)
        created = fields.DateTime(required=True)
        credential_id = fields.String(required=True)
        error = fields.Boolean(required=True)
        frontend_action = fields.String(required=True)
        method = fields.String(required=True)
        req_authn_ctx = fields.List(fields.String, required=True)

    payload = fields.Nested(AuthnPayload)
