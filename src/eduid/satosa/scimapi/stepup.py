"""A micro-SP just to handle the communication towards the StepUp Service for SFO."""

import functools
import json
import logging
from collections.abc import Callable, Iterable, Mapping
from typing import Any, NewType, TypeAlias
from urllib.parse import urlparse

from pydantic import BaseModel, Field, ValidationError

try:
    from common import fetch_mfa_stepup_accounts, get_internal_attribute_name, get_metadata
except ImportError:
    from eduid.satosa.scimapi.common import fetch_mfa_stepup_accounts, get_internal_attribute_name, get_metadata

import satosa.context
import satosa.internal
import satosa.response
import satosa.util as util
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.mdstore import MetaData
from saml2.metadata import create_metadata_string
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED, NameID, Subject
from satosa.attribute_mapping import AttributeMapper
from satosa.backends.saml2 import SAMLBackend
from satosa.context import Context
from satosa.exception import SATOSAAuthenticationError, SATOSAError
from satosa.internal import InternalData
from satosa.micro_services.base import (
    # TODO: Enable when https://github.com/IdentityPython/SATOSA/pull/435 has been accepted;
    # CallbackCallSignature,
    # CallbackReturnType,
    # ProcessReturnType,
    RequestMicroService,
    ResponseMicroService,
)
from satosa.response import Response, SeeOther
from satosa.saml_util import make_saml_response

try:
    # Available in a future version of pysaml2
    from saml2.typing import SAMLBinding, SAMLHttpArgs
except ImportError:
    SAMLBinding = str
    SAMlHttpArgs = dict

logger = logging.getLogger(__name__)

# TODO: Remove when https://github.com/IdentityPython/SATOSA/pull/435 has been accepted
ProcessReturnType: TypeAlias = satosa.internal.InternalData | satosa.response.Response
CallbackReturnType: TypeAlias = satosa.response.Response
CallbackCallSignature = Callable[[satosa.context.Context, Any], CallbackReturnType]
# end todo

REFEDS_MFA = "https://refeds.org/profile/mfa"
IDP_SENT_LOA = "idp_sent_loa"

CONTEXT_NAME = "stepup"
STATE_KEY_LOA = "returned-authn-class"
STATE_KEY_MFA = "requester-authn-class-ref"


class StepUpError(SATOSAError):
    """Generic error for this plugin."""


class LoaSettings(BaseModel):
    requested: list[str]  # LoA that the StepUp-provider understands
    extra_accepted: list[str] = Field(default=[])  # (aliased) LoAs that satisfy the requester
    returned: str | None = (
        None  # LoA that should be returned to the requester, if we get any of the requested + extra_accepted
    )


EntityId = NewType("EntityId", str)
EntityCategory = NewType("EntityCategory", str)
AssuranceCertification = NewType("AssuranceCertification", str)


class MfaConfig(BaseModel):
    by_entity_id: Mapping[EntityId, LoaSettings] = Field(default={})
    by_entity_category: Mapping[EntityCategory, LoaSettings] | None = Field(default={})
    by_assurance_certification: Mapping[AssuranceCertification, LoaSettings] | None = Field(default={})


class MFA(BaseModel):
    mfa: MfaConfig


class StepupPluginConfig(BaseModel):
    mfa: MfaConfig
    sp_config: Mapping[str, Any]
    sign_alg: str | None = None
    digest_alg: str | None = None


class StepupParams(BaseModel):
    issuer: str
    # LoA that the IdP released - as requested through the acr_mapping configuration
    issuer_loa: str | None = None
    requester: EntityId
    # (original) LoAs required by the requester
    requester_loas: list[str]
    # LoA settings to use. Either from the configuration or derived using entity attributes in the metadata.
    loa_settings: LoaSettings


# Applied to response from IDP
class StepUp(ResponseMicroService):
    """
    A micro-SP just to handle the communication towards the StepUp Service for SFO.

    Configuration option:
    - mfa: a mapping between SP entity-ids and LoA settings
    - sp_config: the SP configuration passed to pysaml2

    Example configuration:

      module: stepup.StepUp
      name: stepup
      config:
        # a mapping between SP entity-ids and LoA settings
        # the requested LoA will be requested from the StepUp service
        # the requested, and any extra_accepted LoAs are all the LoAs that satisfy the SP requirements
        # the returned LoA is the LoA that the SP will receive from the proxy
        mfa:
          by_entity_id:
            https://login.idp.eduid.se/idp.xml:
              requested:
                - https://refeds.org/profile/mfa
              returned: https://refeds.org/profile/mfa

          by_assurance_certification:

              https://fidus.skolverket.se/authentication/e-leg:
                requested:
                  - http://id.elegnamnden.se/loa/1.0/loa2
                  - http://id.elegnamnden.se/loa/1.0/loa3
                  - http://id.elegnamnden.se/loa/1.0/loa4
                  - http://id.swedenconnect.se/loa/1.0/uncertified-loa2
                  - http://id.swedenconnect.se/loa/1.0/uncertified-loa3
                  - http://id.swedenconnect.se/loa/1.0/loa2-nonresident
                  - http://id.swedenconnect.se/loa/1.0/loa3-nonresident
                  - http://id.swedenconnect.se/loa/1.0/loa4-nonresident
                  - http://id.elegnamnden.se/loa/1.0/nf-low
                  - http://id.elegnamnden.se/loa/1.0/nf-sub
                  - http://id.elegnamnden.se/loa/1.0/nf-high
                returned: https://refeds.org/profile/mfa

          by_entity_category: {}

        sp_config:
          organization:
            display_name: StepUp Microservice
            name: StepUp Microservice
            url: https://stepup.example.org

          preferred_binding:
              single_sign_on_service:
              - urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect
              - urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST

          contact_person:
          - contact_type: technical
            email_address: technical@example.com
            given_name: Technical
          - contact_type: support
            email_address: support@example.com
            given_name: Support

          metadata:
            local:
            - stepup-service.xml

          key_file: pki/stepup.key
          cert_file: pki/stepup.crt
          want_assertions_or_response_signed: yes

          entityid: <base_url>/<name>/stepup.xml
          service:
            sp:
              name_id_format: ''
              allow_unsolicited: false
              want_response_signed: true
              authn_requests_signed: true
              endpoints:
                assertion_consumer_service:
                - [<base_url>/<name>/acs/post, 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']
                - [<base_url>/<name>/acs/redirect, 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']
    """

    def __init__(self, config: Mapping[str, Any], internal_attributes: dict[str, Any], *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)

        try:
            parsed_config = StepupPluginConfig.model_validate(config)
        except ValidationError as e:
            raise StepUpError(f"The configuration for this plugin is not valid: {e}")

        self.mfa = parsed_config.mfa

        sp_config = json.loads(
            json.dumps(parsed_config.sp_config).replace("<base_url>", self.base_url).replace("<name>", self.name)
        )
        sp_conf = SPConfig().load(sp_config)
        self.sp = Saml2Client(config=sp_conf)
        self.converter = AttributeMapper(internal_attributes)
        self.outstanding_queries: dict[str, SAMLHttpArgs] = {}
        self.attribute_profile = "saml"

        self.converter = AttributeMapper(internal_attributes)

        logger.info("StepUp Authentication is active")

    def _get_params(self, context: satosa.context.Context, data: satosa.internal.InternalData) -> StepupParams:
        _requester: EntityId | None = EntityId(data.requester) if isinstance(data.requester, str) else None
        _loa_settings = get_loa_settings_for_entity_id(_requester, get_metadata(context), self.mfa)
        if not _loa_settings:
            sp_requested = AuthnContext.get_from_state(context=context, state_key=STATE_KEY_MFA)
            returned = sp_requested[0] if sp_requested else None
            _loa_settings = LoaSettings(requested=sp_requested, returned=returned)
        return StepupParams(
            issuer=data.auth_info.issuer if data.auth_info else None,
            requester=_requester,
            issuer_loa=data.auth_info.auth_class_ref if data.auth_info else None,
            requester_loas=AuthnContext.get_from_state(context=context, state_key=STATE_KEY_MFA),
            loa_settings=_loa_settings,
        )

    def process(
        self,
        context: satosa.context.Context,
        data: satosa.internal.InternalData,
    ) -> ProcessReturnType:
        linked_accounts = fetch_mfa_stepup_accounts(data)
        if not linked_accounts:
            logger.info("No linked accounts for this user")
            if AuthnContext.sp_wants_mfa(context=context) and not AuthnContext.idp_sent_loa(context=context):
                logger.info("Requesting SP did ask for MFA but and user has no linked accounts")
                raise SATOSAAuthenticationError(
                    context.state, "Requesting SP did ask for MFA but didn't get it and the user has no linked account"
                )
            return super().process(context, data)

        logger.debug(f"Linked accounts: {linked_accounts}")
        linked_account = linked_accounts[0]

        if not linked_account.entity_id:
            logger.info("No stepup provider for this account")
            return super().process(context, data)

        if not linked_account.identifier:
            logger.info("No account identifier for this account")
            return super().process(context, data)

        if not AuthnContext.sp_wants_mfa(context):
            logger.info("Requesting SP did not ask for MFA")
            return super().process(context, data)

        params = self._get_params(context, data)
        logger.debug(f"StepUp params: {params}")

        # requester did not ask for a specific LoA
        if not params.requester_loas:
            logger.info(f"Requester {params.requester} did not ask for a specific LoA")
            return super().process(context, data)

        if AuthnContext.idp_sent_loa(context):
            logger.info("IDP already sent a LoA")
            return super().process(context, data)

        store_params(data, params)

        name_id = NameID(format=NAMEID_FORMAT_UNSPECIFIED, text=linked_account.identifier)
        subject = Subject(name_id=name_id)
        authn_context = {"authn_context_class_ref": params.loa_settings.requested, "comparison": "exact"}
        relay_state = util.rndstr()

        logger.debug(
            {
                "msg": "Requiring StepUp Authentication",
                "nameid_value": linked_account.identifier,
                "authn_context_class_ref": params.loa_settings.requested,
            }
        )

        try:
            binding, _destination = self.sp.pick_binding(
                service="single_sign_on_service",
                descr_type="idpsso",
                entity_id=linked_account.entity_id,
            )
        except Exception as e:
            error_context = {
                "message": "Failed to pick binding for the AuthnRequest",
                "entity_id": linked_account.entity_id,
            }
            raise StepUpError(error_context) from e

        try:
            req_id: str
            ht_args: Mapping[str, Any]
            req_id, ht_args = self.sp.prepare_for_authenticate(
                entityid=linked_account.entity_id,
                binding=binding,
                response_binding=binding,
                relay_state=relay_state,
                subject=subject,
                requested_authn_context=authn_context,
            )
        except Exception as e:
            _error_context2: Mapping[str, Any] = {
                "message": "Failed to construct the AuthnRequest",
                "entityid": linked_account.entity_id,
                "binding": binding,
                "response_binding": binding,
                "nameid_value": linked_account.identifier,
                "authn_context_class_ref": params.loa_settings.requested,
            }
            raise StepUpError(_error_context2) from e

        if self.sp.config.getattr("allow_unsolicited", "sp") is False:
            if req_id in self.outstanding_queries:
                error_context = {
                    "msg": "request with duplicate id",
                    "req_id": req_id,
                }
                raise SATOSAAuthenticationError(context.state, error_context)
            self.outstanding_queries[req_id] = ht_args

        context.state[self.name] = {
            **context.state.get(self.name, {}),
            "relay_state": relay_state,
            "internal_data": data.to_dict(),
        }
        logger.info("Sending StepUp Authentication")
        logger.debug(f"Binding {binding}, ht_args {ht_args}")
        _response = make_saml_response(binding, ht_args)
        logger.debug(f"Response: {_response}")
        return _response

    def _handle_authn_response(self, context: satosa.context.Context, binding: SAMLBinding) -> CallbackReturnType:
        """
        This is where the user returns after completing a login at the stepup provider.
        """
        logger.info("Returning from StepUp Authentication")

        logger.debug(f"CONTEXT STATE {context.state}")
        _my_state: dict[str, Any] = context.state.get(self.name, {})
        logger.debug(f"My state: {_my_state}")
        data = InternalData.from_dict(_my_state.get("internal_data", {}))
        logger.debug(f"Data: {data}")

        linked_accounts = fetch_mfa_stepup_accounts(data)
        if not linked_accounts:
            # We really shouldn't get here. Did the linked account disappear while the user was logging in?
            raise StepUpError("No linked accounts for this user")

        linked_account = linked_accounts[0]

        # SATOSA won't have decorated the context with the metadata when this endpoint is called,
        # so we need to store it in internal_data (in process() above) and fetch it here.
        params = fetch_params(data)
        if not params:
            logger.info("No params retrieved from internal data")
            raise StepUpError("No params available")

        logger.debug(f"Stepup parameters: {params}")

        try:
            _response: str = context.request["SAMLResponse"]
            authn_response = self.sp.parse_authn_request_response(
                _response,
                binding,
                outstanding=self.outstanding_queries,
            )
        except Exception as e:
            _error_context: Mapping[str, Any] = {
                "message": "Failed to parse SAML Response",
                "requester": params.requester,
                "request": context.request.get("SAMLResponse"),
                "context": context,
            }
            raise StepUpError(_error_context) from e

        if not authn_response:
            raise StepUpError("Failed to parse SAML Response")

        if self.sp.config.getattr("allow_unsolicited", "sp") is not True:
            req_id = authn_response.in_response_to
            if not req_id or req_id not in self.outstanding_queries:
                _error_context = {
                    "msg": "no outstanding request with such id",
                    "req_id": req_id,
                }
                raise SATOSAAuthenticationError(context.state, _error_context)
            self.outstanding_queries.pop(req_id)

        stepup_issuer = (
            authn_response.response.issuer.text if authn_response.response and authn_response.response.issuer else None
        )
        is_stepup_provider = bool(stepup_issuer == linked_account.entity_id)

        # Verify the subject identified in the AuthnRequest
        # is returned in the expected attribute of the AuthnResponse
        is_subject_identified = False
        stepup_user_identifier = authn_response.ava.get(linked_account.attribute, []) if authn_response.ava else []
        is_subject_identified = linked_account.identifier in stepup_user_identifier

        stepup_loa = next(iter(authn_response.authn_info()), [None])[0]
        is_stepup_loa_exact = bool(stepup_loa and stepup_loa in params.loa_settings.requested)
        is_mfa_satisfied = is_loa_requirements_satisfied(params.loa_settings, stepup_loa)

        is_stepup_successful = is_stepup_provider and is_subject_identified and is_stepup_loa_exact and is_mfa_satisfied

        logger.info(
            {
                "msg": "Received StepUp Response",
                "linked_account": linked_account,
                "stepup_loa": stepup_loa,
                "is_stepup_provider": is_stepup_provider,
                "is_stepup_loa_exact": is_stepup_loa_exact,
                "is_subject_identified": is_subject_identified,
                "is_mfa_satisfied": is_mfa_satisfied,
                "is_stepup_successful": is_stepup_successful,
            }
        )

        logger.debug(
            {
                "user_identifier": linked_account.identifier,
                "stepup_user_identifier": stepup_user_identifier,
            }
        )

        if not is_stepup_successful:
            error_context = {
                "message": "StepUp authentication failed",
                "params": params,
                "linked_account": linked_account,
                "stepup_loa": stepup_loa,
                "is_stepup_provider": is_stepup_provider,
                "is_stepup_loa_exact": is_stepup_loa_exact,
                "is_subject_identified": is_subject_identified,
                "is_mfa_satisfied": is_mfa_satisfied,
                "is_stepup_successful": is_stepup_successful,
            }
            raise StepUpError(error_context)

        # the SAML attribute that holds the assurances for this step-up provider/issuer
        stepup_assurances = authn_response.ava.get(linked_account.assurance, []) if authn_response.ava else []
        # the internal attribute that holds the assurances
        int_assurance_attribute_name = get_internal_attribute_name(self.converter, linked_account.assurance)
        # add the new assurances
        data.attributes[int_assurance_attribute_name] = [
            *data.attributes.get(int_assurance_attribute_name, []),
            *stepup_assurances,
        ]

        data.auth_info.auth_class_ref = next(iter(params.requester_loas), stepup_loa)
        res = super().process(context, data)
        if not isinstance(res, Response):
            # process() is a chain of calls to microservices. The last one in the chain will always return a Response,
            # but the call signature have to allow the InternalData to be returned as well.
            raise RuntimeError("Unexpected response type")
        return res

    def _metadata_endpoint(self, context: satosa.context.Context, extra: Any) -> CallbackReturnType:
        metadata_string = create_metadata_string(None, self.sp.config, 4, None, None, None, None, None).decode("utf-8")
        return Response(metadata_string, content="text/xml")

    def register_endpoints(self) -> list[tuple[str, CallbackCallSignature]]:
        url_map: list[tuple[str, CallbackCallSignature]] = []

        # acs endpoints
        sp_endpoints: dict[str, list[tuple[str, str]]] = self.sp.config.getattr("endpoints", "sp")
        for endp, binding in sp_endpoints["assertion_consumer_service"]:
            parsed_endp = urlparse(endp)
            url_map.append(
                (
                    f"^{parsed_endp.path[1:]}$",
                    functools.partial(self._handle_authn_response, binding=SAMLBinding(binding)),
                )
            )

        # metadata endpoint
        parsed_entity_id = urlparse(self.sp.config.entityid)
        url_map.append(
            (
                f"^{parsed_entity_id.path[1:]}$",
                functools.partial(self._metadata_endpoint, extra=None),
            )
        )

        logger.debug(f"Registering endpoints: {url_map}")

        return url_map


# applied to incoming request from SP
class AuthnContext(RequestMicroService):
    """
    A micro-service that runs when the authnRequest is first received from the SP.

    It saves the original requested authn context class reference (accr) in the state.
    """

    def __init__(self, config: Mapping[str, Any], internal_attributes: dict[str, Any], *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)

        try:
            parsed_config = MFA.model_validate(config)
        except ValidationError as e:
            raise StepUpError(f"The configuration for this plugin is not valid: {e}")

        self.mfa = parsed_config.mfa

    def process(
        self,
        context: satosa.context.Context,
        data: satosa.internal.InternalData,
    ) -> ProcessReturnType:
        assert context.state is not None  # please type checking
        loa_settings = get_loa_settings_for_entity_id(
            EntityId(data.requester), [context.internal_data.get(Context.KEY_METADATA_STORE)], self.mfa
        )
        if loa_settings:
            logger.debug(f"Requesting authnContextClassRef {loa_settings.requested} from {data.requester}")
            self.save_to_state(context=context, state_key=STATE_KEY_MFA, data=loa_settings.requested)
        else:
            self.save_to_state(
                context=context,
                state_key=STATE_KEY_MFA,
                data=context.get_decoration(Context.KEY_AUTHN_CONTEXT_CLASS_REF),
            )

        return super().process(context, data)

    @staticmethod
    def save_to_state(context: Context, state_key: str, data: list[str]) -> None:
        logger.debug(f"Saving to state to context {CONTEXT_NAME}, {data} (state_key: {state_key})")
        context.state[CONTEXT_NAME] = {
            **context.state.get(CONTEXT_NAME, {}),
            state_key: data,
        }

    @staticmethod
    def get_from_state(context: Context, state_key: str) -> list[str]:
        _res = context.state.get(CONTEXT_NAME, {}).get(state_key, [])
        logger.debug(f"Retrieved state from context {CONTEXT_NAME}: {_res} (state_key: {state_key})")
        return _res

    @staticmethod
    def sp_wants_mfa(context: Context, state_key: str = STATE_KEY_MFA) -> bool:
        res = REFEDS_MFA in AuthnContext.get_from_state(context, state_key)
        logger.debug(f"Requesting service provider wants REFEDS MFA: {res}")
        return res

    @staticmethod
    def idp_sent_loa(context: Context, state_key: str = STATE_KEY_LOA) -> bool:
        res = IDP_SENT_LOA in AuthnContext.get_from_state(context, state_key)
        logger.debug(f"IdP sent loa: {res}")
        return res


def get_loa_settings_for_entity_id(
    entity_id: EntityId | None, metadata: Iterable[MetaData], mfa: MfaConfig | None
) -> LoaSettings | None:
    """
    SP: Return setting from by_entity_id or by_entity_category.
    IDP: Return settings from by_entity_id or by_assurance_certification.
    """

    logger.debug(f"Looking for LoA settings based on entity id {entity_id}")
    if entity_id is None:
        return None
    if mfa is None:
        logger.debug("No MFA config present")
        return None
    if entity_id in mfa.by_entity_id:
        logger.debug(f"Loaded LoA settings from configuration based on entity id {entity_id}")
        return mfa.by_entity_id[entity_id]
    for _this_md in metadata:
        if not _this_md:
            continue
        _ecs: list[EntityCategory]
        try:
            _ecs = _this_md.entity_categories(entity_id)
        except KeyError:
            _ecs = []
        logger.debug(f"Entity categories for {entity_id}: {_ecs}")
        for _ec in _ecs:
            if mfa.by_entity_category:
                if _ec in mfa.by_entity_category:
                    logger.debug(f"Loaded LoA settings based on entity category {_ec}")
                    return mfa.by_entity_category[_ec]
        try:
            _assurances = list(_this_md.assurance_certifications(entity_id))
        except Exception:
            _assurances = []
        logger.debug(f"Assurance certifications for {entity_id}: {_assurances}")
        for _ac in _assurances:
            if mfa.by_assurance_certification:
                if _ac in mfa.by_assurance_certification:
                    logger.debug(f"Loaded LoA settings based on assurance certification {_ac}")
                    return mfa.by_assurance_certification[_ac]

    return None


class StepupSAMLBackend(SAMLBackend):
    """
    A SAML backend to request custom authn context class references from IdP:s with certain entity attributes.
    """

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.mfa: MfaConfig | None = None

        try:
            parsed_config = StepupPluginConfig.model_validate(self.config)
        except ValidationError as e:
            raise StepUpError(f"The configuration for this plugin is not valid: {e}")
        self.mfa = parsed_config.mfa

    def authn_request(self, context: satosa.context.Context, entity_id: str) -> SeeOther | Response:
        logger.debug(f"Processing AuthnRequest with entity id {repr(entity_id)}")

        if self.mfa and AuthnContext.sp_wants_mfa(context=context):
            loa_settings = get_loa_settings_for_entity_id(EntityId(entity_id), [self.sp.metadata], self.mfa)
            logger.debug(f"LoA settings for {entity_id}: {loa_settings}")
            if loa_settings:
                logger.debug(f"Requesting authnContextClassRef {loa_settings.requested} from {entity_id}")
                context.state[Context.KEY_TARGET_AUTHN_CONTEXT_CLASS_REF] = loa_settings.requested

        target_accr = context.state.get(Context.KEY_TARGET_AUTHN_CONTEXT_CLASS_REF)
        logger.debug(f"Proceeding with ACCR {target_accr}")

        return super().authn_request(context, entity_id)


class RewriteAuthnContextClass(ResponseMicroService):
    """
    When we receive a response from an IdP, we check if we have configuration specifying
    'normalisation' of the authn context class reference in our MFA configuration.
    """

    def __init__(self, config: Mapping[str, Any], internal_attributes: dict[str, Any], *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.mfa: MfaConfig | None = None

        try:
            parsed_config = MFA.model_validate(config)
        except ValidationError as e:
            raise StepUpError(f"The configuration for this plugin is not valid: {e}")
        self.mfa = parsed_config.mfa

    def process(
        self,
        context: satosa.context.Context,
        data: satosa.internal.InternalData,
    ) -> ProcessReturnType:
        if self.mfa and AuthnContext.sp_wants_mfa(context):
            _issuer = data.auth_info.issuer if data.auth_info else None
            _loa_settings = None
            _params = fetch_params(data)
            if _params:
                _loa_settings = _params.loa_settings
            if not _loa_settings:
                _loa_settings = get_loa_settings_for_entity_id(
                    _issuer, [context.internal_data.get(Context.KEY_METADATA_STORE)], self.mfa
                )

            logger.debug(f"LoA settings for {_issuer}: {_loa_settings}")
            if _loa_settings and _loa_settings.returned:
                _asserted_loa: str | None = data.auth_info.auth_class_ref
                if _asserted_loa in _loa_settings.requested or _asserted_loa in _loa_settings.extra_accepted:
                    logger.info(
                        "Rewriting authnContextClassRef in response from "
                        f"{_asserted_loa} to {_loa_settings.returned}"
                    )
                    data.auth_info.auth_class_ref = _loa_settings.returned
                    AuthnContext.save_to_state(context=context, state_key=STATE_KEY_LOA, data=[IDP_SENT_LOA])
                else:
                    logger.info(f"AuthnContextClassRef {_asserted_loa} not accepted")
                    raise StepUpError(f"AuthnContextClassRef {_asserted_loa} not accepted")

        return super().process(context, data)


def is_loa_requirements_satisfied(settings: LoaSettings | None, loa: str | None) -> bool:
    if not settings:
        return False
    satisfied = loa in settings.requested or loa in settings.extra_accepted
    return satisfied


def store_params(data: satosa.internal.InternalData, params: StepupParams) -> None:
    """Store the LoA settings in the internal data"""
    # `data` needs to be JSON serialisable
    data.stepup_params = params.dict()


def fetch_params(data: satosa.internal.InternalData) -> StepupParams | None:
    """Retrieve the LoA settings from the internal data"""
    if not hasattr(data, "stepup_params") or not isinstance(data.stepup_params, dict):
        return None
    return StepupParams.model_validate(data.stepup_params)
