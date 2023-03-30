"""A micro-SP just to handle the communication towards the StepUp Service for SFO."""

import functools
import json
import logging
from os import link
from typing import Any, Mapping, NewType, Optional
from urllib.parse import urlparse
from pydantic import BaseModel, ValidationError, validator
from eduid.satosa.scimapi.common import fetch_mfa_stepup_accounts, get_internal_attribute_name

import satosa.util as util
import satosa.context
import satosa.internal
import satosa.response
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.metadata import create_metadata_string
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED, NameID, Subject
from saml2.typing import SAMLBinding, SAMLHttpArgs
from satosa.attribute_mapping import AttributeMapper
from satosa.context import Context
from satosa.exception import SATOSAAuthenticationError, SATOSAError
from satosa.internal import InternalData
from satosa.micro_services.base import (
    RequestMicroService,
    ResponseMicroService,
    ProcessReturnType,
    CallbackReturnType,
    CallbackCallSignature,
)
from satosa.response import Response
from satosa.saml_util import make_saml_response

logger = logging.getLogger(__name__)
KEY_REQ_AUTHNCLASSREF = "requester-authn-class-ref"


def is_loa_requirements_satisfied(accepted_loas: list[str], loa: Optional[str]) -> bool:
    satisfied = loa in accepted_loas
    return satisfied


class StepUpError(SATOSAError):
    """Generic error for this plugin."""


class LoaSettings(BaseModel):
    required: str  # LoA that the StepUp-provider understands
    accepted: list[str]  # (aliased) LoAs that satisfy the requester

    @validator("required")
    def required_loa_must_be_in_accepted(cls, v: str, values: Mapping[str, Any]) -> str:
        if v not in values["accepted"]:
            raise ValueError("required LoA must be in accepted LoAs")
        return v


EntityId = NewType("EntityId", str)


class PluginConfig(BaseModel):
    mfa: Mapping[EntityId, LoaSettings]
    sp_config: Mapping[str, Any]
    sign_alg: str
    digest_alg: str


class StepupParams(BaseModel):
    issuer: str
    issuer_loa: Optional[str]  # LoA that the IdP released - as requested through the acr_mapping configuration
    requester: EntityId
    requester_loas: list[str]  # (original) LoAs required by the requester
    loa_settings: Optional[LoaSettings]  # LoA settings for the requester


class AuthnContext(RequestMicroService):
    def process(
        self,
        context: satosa.context.Context,
        data: satosa.internal.InternalData,
    ) -> ProcessReturnType:
        assert context.state is not None  # please type checking
        context.state[self.name] = {
            **context.state.get(self.name, {}),
            KEY_REQ_AUTHNCLASSREF: context.get_decoration(Context.KEY_AUTHN_CONTEXT_CLASS_REF),
        }
        return super().process(context, data)


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
        # the required LoA will be requested from the StepUp service
        # the accepted LoAs are all the LoAs that satisfy the SP requirements
        mfa:
          some-service-entityid:
            required: some-loa-2
            accepted:
              - some-loa-2
              - some-loa-3
          https://sp.satosa.docker/sp.xml:
            required: urn:oasis:names:tc:SAML:2.0:ac:classes:mfa
            accepted:
              - urn:oasis:names:tc:SAML:2.0:ac:classes:mfa

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

        # 'mfa' should be a mapping between entity_id and loa_settings
        try:
            parsed_config = PluginConfig.parse_obj(config)
        except ValidationError as e:
            raise StepUpError(f"The configuration for this plugin is not valid: {e}")

        self.mfa = parsed_config.mfa
        sp_config = json.loads(
            json.dumps(parsed_config.sp_config).replace("<base_url>", self.base_url).replace("<name>", self.name)
        )
        sp_conf = SPConfig().load(sp_config)
        self.sp = Saml2Client(config=sp_conf)
        self.converter = AttributeMapper(internal_attributes)
        # self.encryption_keys = []
        self.outstanding_queries: dict[str, SAMLHttpArgs] = {}
        self.attribute_profile = "saml"

        self.converter = AttributeMapper(internal_attributes)

        logger.info("StepUp Authentication is active")

    def _get_params(self, context: satosa.context.Context, data: satosa.internal.InternalData) -> StepupParams:
        _loa_settings: Optional[LoaSettings] = None
        if data.requester is not None and data.requester in self.mfa:
            _loa_settings = self.mfa[EntityId(data.requester)]
        return StepupParams(
            issuer=data.auth_info.issuer,
            requester=data.requester,
            issuer_loa=data.auth_info.auth_class_ref,
            requester_loas=context.state.get(self.name, {}).get(KEY_REQ_AUTHNCLASSREF, []),
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
            return super().process(context, data)

        linked_account = linked_accounts[0]

        if not linked_account.entity_id:
            logger.info("No stepup provider for this account")
            return super().process(context, data)

        if not linked_account.identifier:
            logger.info("No account identifier for this account")
            return super().process(context, data)

        params = self._get_params(context, data)

        # requester did not ask for a specific LoA
        is_requester_expecting_loa = bool(params.requester_loas)
        if not is_requester_expecting_loa:
            logger.info("Requester did not ask for a specific LoA")
            return super().process(context, data)

        # requester is not configured
        is_requester_configured = bool(params.loa_settings and params.loa_settings.required)
        if not is_requester_configured:
            logger.info("Requester is not configured")
            return super().process(context, data)

        # no need to step-up - required LoA is already met
        is_mfa_satisfied = params.loa_settings and is_loa_requirements_satisfied(
            params.loa_settings.accepted, params.issuer_loa
        )
        if is_mfa_satisfied:
            logger.info("No need to step-up - required LoA is already met")
            return super().process(context, data)

        assert params.loa_settings  # please mypy, already checked above since we return if is_stepup_skipped

        name_id = NameID(format=NAMEID_FORMAT_UNSPECIFIED, text=linked_account.identifier)
        subject = Subject(name_id=name_id)
        authn_context = {"authn_context_class_ref": [params.loa_settings.required], "comparison": "exact"}
        relay_state = util.rndstr()

        logger.debug(
            {
                "msg": "Requiring StepUp Authentication",
                "nameid_value": linked_account.identifier,
                "authn_context_class_ref": params.loa_settings.required,
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
                "authn_context_class_ref": params.loa_settings.required,
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
        return make_saml_response(binding, ht_args)

    def _handle_authn_response(self, context: satosa.context.Context, binding: SAMLBinding) -> CallbackReturnType:
        internal_data_dict: dict[str, Any] = {}
        if "internal_data" in context.state:
            internal_data_dict = context.state["internal_data"]
        data = InternalData.from_dict(internal_data_dict)

        linked_accounts = fetch_mfa_stepup_accounts(data)
        if not linked_accounts:
            logger.info("No linked accounts for this user")
            raise StepUpError("No linked accounts for this user")

        linked_account = linked_accounts[0]

        params = self._get_params(context, data)

        # mfa_stepup_accounts = getattr(data, "mfa_stepup_accounts", [])
        # linked_account: Mapping[str, str] = next(iter(mfa_stepup_accounts), {})
        # stepup_provider = linked_account["entity_id"]
        # user_identifier = linked_account["identifier"]
        # user_identifier_attribute = linked_account["attribute"]

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

        if self.sp.config.getattr("allow_unsolicited", "sp") is False:
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

        assert params.loa_settings  # please mypy
        stepup_loa = next(iter(authn_response.authn_info()), [None])[0]
        is_stepup_loa_exact = bool(stepup_loa and stepup_loa == params.loa_settings.required)
        is_mfa_satisfied = is_loa_requirements_satisfied(params.loa_settings.accepted, stepup_loa)

        is_stepup_successful = is_stepup_provider and is_subject_identified and is_stepup_loa_exact and is_mfa_satisfied

        logger.info(
            {
                "msg": "Received StepUp Response",
                "params": params,
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
                    functools.partial(self._handle_authn_response, binding=binding),
                )
            )

        # metadata endpoint
        parsed_entity_id = urlparse(self.sp.config.entityid)
        url_map.append(
            (
                f"^{parsed_entity_id.path[1:]}",
                functools.partial(self._metadata_endpoint, extra=None),
            )
        )

        return url_map
