from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid.webapp.common.api.schemas.identity import IdentitiesSchema, NinSchema
from eduid.webapp.common.api.schemas.ladok import LadokSchema
from eduid.webapp.common.api.schemas.orcid import OrcidSchema
from eduid.webapp.email.schemas import EmailSchema
from eduid.webapp.personal_data.validators import validate_language, validate_nonempty
from eduid.webapp.phone.schemas import PhoneSchema

__author__ = "eperez"


class PersonalDataRequestSchema(EduidSchema, CSRFRequestMixin):
    given_name = fields.String(required=True, validate=[validate_nonempty])
    surname = fields.String(required=True, validate=[validate_nonempty])
    # TODO: remove display_name when frontend stops sending it
    display_name = fields.String(required=False)
    language = fields.String(required=True, default="en", validate=validate_language)


class PersonalDataSchema(EduidSchema):
    given_name = fields.String(required=True, attribute="givenName")
    surname = fields.String(required=True)
    display_name = fields.String(required=True, attribute="displayName")
    language = fields.String(required=True, attribute="preferredLanguage")


class PersonalDataResponseSchema(FluxStandardAction):
    class PersonalDataResponsePayload(PersonalDataSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(PersonalDataResponsePayload)


class IdentitiesResponseSchema(FluxStandardAction):
    class IdentitiesResponsePayload(EmailSchema, CSRFResponseMixin):
        identities = fields.Nested(IdentitiesSchema)

    payload = fields.Nested(IdentitiesResponsePayload)


class AllDataSchema(EduidSchema):
    eppn = fields.String(required=True, attribute="eduPersonPrincipalName")
    given_name = fields.String(required=True, attribute="givenName")
    surname = fields.String(required=True)
    display_name = fields.String(required=True, attribute="displayName")
    language = fields.String(required=True, attribute="preferredLanguage", validate=validate_language)
    identities = fields.Nested(IdentitiesSchema)
    emails = fields.Nested(EmailSchema, many=True, attribute="mailAliases")
    phones = fields.Nested(PhoneSchema, many=True, attribute="phone")
    orcid = fields.Nested(OrcidSchema, attribute="orcid")
    ladok = fields.Nested(LadokSchema, attribute="ladok")


class AllDataResponseSchema(FluxStandardAction):
    class AllDataResponsePayload(AllDataSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(AllDataResponsePayload)
