from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid.webapp.common.api.schemas.identity import IdentitiesSchema
from eduid.webapp.common.api.schemas.ladok import LadokSchema
from eduid.webapp.common.api.schemas.orcid import OrcidSchema
from eduid.webapp.email.schemas import EmailSchema
from eduid.webapp.personal_data.validators import validate_language, validate_nonempty
from eduid.webapp.phone.schemas import PhoneSchema

__author__ = "eperez"


class PersonalDataRequestSchema(EduidSchema, CSRFRequestMixin):
    given_name = fields.String(required=True, validate=[validate_nonempty])
    chosen_given_name = fields.String(required=False)
    surname = fields.String(required=True, validate=[validate_nonempty])
    legal_name = fields.String(required=False)
    language = fields.String(required=True, default="en", validate=validate_language)


class PersonalDataSchema(EduidSchema):
    given_name = fields.String(required=True, attribute="givenName")
    chosen_given_name = fields.String(required=False)
    surname = fields.String(required=True)
    legal_name = fields.String(required=False)
    language = fields.String(required=True, attribute="preferredLanguage")

class UserNameRequestSchema(EduidSchema, CSRFRequestMixin):
    given_name = fields.String(required=True, validate=[validate_nonempty])
    chosen_given_name = fields.String(required=False)
    surname = fields.String(required=True, validate=[validate_nonempty])
    legal_name = fields.String(required=False)

class UserNameSchema(EduidSchema):
    given_name = fields.String(required=True, attribute="givenName")
    chosen_given_name = fields.String(required=False)
    surname = fields.String(required=True)
    legal_name = fields.String(required=False)
    language = fields.String(required=True, attribute="preferredLanguage")


class UserLanguageRequestSchema(EduidSchema, CSRFRequestMixin):
    language = fields.String(required=True, default="en", validate=validate_language)

class UserLanguageSchema(EduidSchema):
    language = fields.String(required=True, attribute="preferredLanguage")

class UserPreferencesSchema(EduidSchema):
    always_use_security_key = fields.Boolean(required=True, default=True)


class UserPreferencesRequestSchema(UserPreferencesSchema, CSRFRequestMixin):
    pass


class UserPreferencesResponseSchema(FluxStandardAction):
    class UserPreferencesResponsePayload(UserPreferencesSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(UserPreferencesResponsePayload)


class PersonalDataResponseSchema(FluxStandardAction):
    class PersonalDataResponsePayload(PersonalDataSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(PersonalDataResponsePayload)

class UserNameResponseSchema(FluxStandardAction):
    class UserNameResponsePayload(UserNameSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(UserNameResponsePayload)


class UserLanguageResponseSchema(FluxStandardAction):
    class UserLanguageResponsePayload(UserLanguageSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(UserLanguageResponsePayload)


class IdentitiesResponseSchema(FluxStandardAction):
    class IdentitiesResponsePayload(EmailSchema, CSRFResponseMixin):
        identities = fields.Nested(IdentitiesSchema)

    payload = fields.Nested(IdentitiesResponsePayload)


class AllDataSchema(EduidSchema):
    eppn = fields.String(required=True, attribute="eduPersonPrincipalName")
    given_name = fields.String(required=True, attribute="givenName")
    chosen_given_name = fields.String(required=False)
    surname = fields.String(required=True)
    legal_name = fields.String(required=False)
    language = fields.String(required=True, attribute="preferredLanguage", validate=validate_language)
    identities = fields.Nested(IdentitiesSchema)
    emails = fields.Nested(EmailSchema, many=True, attribute="mailAliases")
    phones = fields.Nested(PhoneSchema, many=True, attribute="phone")
    orcid = fields.Nested(OrcidSchema, attribute="orcid")
    ladok = fields.Nested(LadokSchema, attribute="ladok")
    preferences = fields.Nested(UserPreferencesSchema, attribute="preferences")


class AllDataResponseSchema(FluxStandardAction):
    class AllDataResponsePayload(AllDataSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(AllDataResponsePayload)
