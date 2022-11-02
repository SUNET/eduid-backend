"""A micro-SP just to handle the communication towards the StepUp Service for SFO."""

import functools
import json
import logging
from typing import Callable, Iterable, List, Mapping, Tuple
from urllib.parse import urlparse

import satosa.util as util
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.metadata import create_metadata_string
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED, NameID, Subject
from satosa.attribute_mapping import AttributeMapper
from satosa.context import Context
from satosa.exception import SATOSAAuthenticationError, SATOSAError
from satosa.internal import InternalData
from satosa.micro_services.base import RequestMicroService, ResponseMicroService
from satosa.response import Response
from satosa.saml_util import make_saml_response

logger = logging.getLogger(__name__)
KEY_REQ_AUTHNCLASSREF = "requester-authn-class-ref"


def is_loa_requirements_satisfied(accepted_loas, loa):
    satisfied = loa in accepted_loas
    return satisfied


class StepUpError(SATOSAError):
    """Generic error for this plugin."""


class AuthnContext(RequestMicroService):
    def process(self, context, data):
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

    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)

        mfa = config.get("mfa")

        mfa_is_a_mapping = isinstance(mfa, Mapping)
        mfa_has_at_least_one_entry = mfa_is_a_mapping and len(mfa)
        mfa_entityid_is_string = mfa_is_a_mapping and all(type(entityid) is str for entityid in mfa.keys())
        mfa_loa_settings_is_a_mapping = mfa_is_a_mapping and all(
            isinstance(loa_settings, Mapping) for entityid, loa_settings in mfa.items()
        )
        mfa_loa_settings_has_required_field = mfa_loa_settings_is_a_mapping and all(
            "required" in loa_settings.keys() and type(loa_settings["required"]) is str
            for entityid, loa_settings in mfa.items()
        )
        mfa_loa_settings_has_accepted_field = mfa_loa_settings_is_a_mapping and all(
            "accepted" in loa_settings.keys()
            and isinstance(loa_settings["accepted"], Iterable)
            and all(type(loa) is str for loa in loa_settings["accepted"])
            for entityid, loa_settings in mfa.items()
        )
        mfa_loa_required_is_included_in_accepted = (
            mfa_loa_settings_has_accepted_field
            and mfa_loa_settings_has_required_field
            and all(loa_settings["required"] in loa_settings["accepted"] for entityid, loa_settings in mfa.items())
        )
        sign_alg_is_a_string = type(config.get("sign_alg", "")) is str
        digest_alg_is_a_string = type(config.get("digest_alg", "")) is str

        validators = {
            "mfa_is_a_mapping": mfa_is_a_mapping,
            "mfa_has_at_least_one_entry": mfa_has_at_least_one_entry,
            "mfa_entityid_is_string": mfa_entityid_is_string,
            "mfa_loa-settings_is_a_mapping": mfa_loa_settings_is_a_mapping,
            "mfa_loa-settings_has_required_field": mfa_loa_settings_has_required_field,
            "mfa_loa-settings_has_accepted_field": mfa_loa_settings_has_accepted_field,
            "mfa_loa_required_is_included_in_accepted": mfa_loa_required_is_included_in_accepted,
            "sign_alg_is_a_string": sign_alg_is_a_string,
            "digest_alg_is_a_string": digest_alg_is_a_string,
        }
        if not all(validators.values()):
            error_context = {
                "message": (
                    "The configuration for this plugin is not valid. "
                    "Make sure that the following rules are met: "
                    ", ".join(rule.replace("_", " ") for rule in validators.keys())
                ),
                "validators": validators,
            }
            raise StepUpError(error_context)

        self.mfa = mfa
        sp_config = json.loads(
            json.dumps(config["sp_config"]).replace("<base_url>", self.base_url).replace("<name>", self.name)
        )
        sp_conf = SPConfig().load(sp_config)
        self.sp = Saml2Client(config=sp_conf)
        self.converter = AttributeMapper(internal_attributes)
        self.encryption_keys = []
        self.outstanding_queries = {}
        self.attribute_profile = "saml"

        logger.info("StepUp Authentication is active")

    def process(self, context, data):
        issuer = data.auth_info.issuer
        requester = data.requester

        # LoA that the IdP released - as requested through the acr_mapping configuration
        issuer_loa = data.auth_info.auth_class_ref
        # (original) LoAs required by the requester
        requester_loas = context.state.get(self.name, {}).get(KEY_REQ_AUTHNCLASSREF, [])
        # (aliased) LoAs that satisfy the requester
        accepted_loas = self.mfa.get(requester, {}).get("accepted") or []
        # LoA that the StepUp-provider understands
        required_loa = self.mfa.get(requester, {}).get("required")

        mfa_stepup_accounts = getattr(data, "mfa_stepup_accounts", [])
        linked_account: Mapping[str, str] = next(iter(mfa_stepup_accounts), {})
        stepup_provider = linked_account.get("entity_id")
        nameid_value = linked_account.get("identifier")

        # no stepup provider for this account
        is_account_stepup_provider_set = bool(stepup_provider)
        # no account identifier
        is_account_identifier_set = bool(nameid_value)
        # requester did not ask for a specific LoA
        is_requester_expecting_loa = bool(requester_loas)
        # requester is not configured
        is_requester_configured = bool(required_loa)
        # no need to step-up - required LoA is already met
        is_mfa_satisfied = is_loa_requirements_satisfied(accepted_loas, issuer_loa)

        # should stepup proceed
        is_stepup_skipped = (
            is_mfa_satisfied
            or not is_account_stepup_provider_set
            or not is_account_identifier_set
            or not is_requester_expecting_loa
            or not is_requester_configured
        )

        # XXX is_stepup_skipped vs is_mfa_satisfied
        # should we skip stepup if not is_mfa_satisfied?
        # maybe we should check if not is_mfa_satisfied and raise an error
        # else, if is_stepup_skipped, skip
        # else, continue

        logger.info(
            {
                "msg": "Starting StepUp Authentication",
                "issuer": issuer,
                "requester": requester,
                "issuer_loa": issuer_loa,
                "requester_loas": requester_loas,
                "accepted_loas": accepted_loas,
                "required_loa": required_loa,
                "linked_account": linked_account,
                "is_account_stepup_provider_set": is_account_stepup_provider_set,
                "is_account_identifier_set": is_account_identifier_set,
                "is_requester_expecting_loa": is_requester_expecting_loa,
                "is_requester_configured": is_requester_configured,
                "is_mfa_satisfied": is_mfa_satisfied,
                "is_stepup_skipped": is_stepup_skipped,
            }
        )

        if is_stepup_skipped:
            return super().process(context, data)

        name_id = NameID(format=NAMEID_FORMAT_UNSPECIFIED, text=nameid_value)
        subject = Subject(name_id=name_id)
        authn_context = {"authn_context_class_ref": [required_loa], "comparison": "exact"}
        relay_state = util.rndstr()

        logger.debug(
            {
                "msg": "Requiring StepUp Authentication",
                "nameid_value": nameid_value,
                "authn_context_class_ref": required_loa,
            }
        )

        try:
            binding, destination = self.sp.pick_binding(
                service="single_sign_on_service",
                descr_type="idpsso",
                entity_id=stepup_provider,
            )
        except Exception as e:
            error_context = {
                "message": "Failed to pick binding for the AuthnRequest",
                "entity_id": stepup_provider,
            }
            raise StepUpError(error_context) from e

        try:
            req_id, ht_args = self.sp.prepare_for_authenticate(
                entityid=stepup_provider,
                binding=binding,
                response_binding=binding,
                relay_state=relay_state,
                subject=subject,
                requested_authn_context=authn_context,
            )
        except Exception as e:
            error_context = {
                "message": "Failed to construct the AuthnRequest",
                "entityid": stepup_provider,
                "binding": binding,
                "response_binding": binding,
                "nameid_value": nameid_value,
                "authn_context_class_ref": required_loa,
            }
            raise StepUpError(error_context) from e

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

    def _handle_authn_response(self, context, binding):
        internal_data_dict = context.state.get(self.name, {}).get("internal_data")
        data = InternalData.from_dict(internal_data_dict)

        issuer = data.auth_info.issuer
        requester = data.requester

        # LoA that the IdP released - as requested through the acr_mapping configuration
        issuer_loa = data.auth_info.auth_class_ref
        # (original) LoAs required by the requester
        requester_loas = context.state.get(self.name, {}).get(KEY_REQ_AUTHNCLASSREF, [])
        # (aliased) LoAs that satisfy the requester
        accepted_loas = self.mfa.get(requester, {}).get("accepted") or []
        # LoA that the StepUp-provider understands
        required_loa = self.mfa.get(requester, {}).get("required")

        mfa_stepup_accounts = getattr(data, "mfa_stepup_accounts", [])
        linked_account: Mapping[str, str] = next(iter(mfa_stepup_accounts), {})
        stepup_provider = linked_account["entity_id"]
        user_identifier = linked_account["identifier"]
        user_identifier_attribute = linked_account["attribute"]

        try:
            authn_response = self.sp.parse_authn_request_response(
                context.request["SAMLResponse"],
                binding,
                outstanding=self.outstanding_queries,
            )
        except Exception as e:
            error_context = {
                "message": "Failed to parse SAML Response",
                "requester": requester,
                "request": context.request.get("SAMLResponse"),
                "context": context,
            }
            raise StepUpError(error_context) from e

        if self.sp.config.getattr("allow_unsolicited", "sp") is False:
            req_id = authn_response.in_response_to
            if req_id not in self.outstanding_queries:
                error_context = {
                    "msg": "no outstanding request with such id",
                    "req_id": req_id,
                }
                raise SATOSAAuthenticationError(context.state, error_context)
            self.outstanding_queries.pop(req_id)

        stepup_issuer = authn_response.response.issuer.text
        is_stepup_provider = stepup_issuer == stepup_provider

        # Verify the subject identified in the AuthnRequest
        # is returned in the expected attribute of the AuthnResponse
        is_subject_identified = False
        stepup_user_identifier = authn_response.ava.get(user_identifier_attribute, [])
        is_subject_identified = user_identifier in stepup_user_identifier

        stepup_loa = next(iter(authn_response.authn_info()), [None])[0]
        is_stepup_loa_exact = stepup_loa == required_loa
        is_mfa_satisfied = is_loa_requirements_satisfied(accepted_loas, stepup_loa)

        is_stepup_successful = is_stepup_provider and is_subject_identified and is_stepup_loa_exact and is_mfa_satisfied

        logger.info(
            {
                "msg": "Received StepUp Response",
                "issuer": issuer,
                "requester": requester,
                "stepup_provider": stepup_provider,
                "issuer_loa": issuer_loa,
                "requester_loas": requester_loas,
                "accepted_loas": accepted_loas,
                "required_loa": required_loa,
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
                "user_identifier": user_identifier,
                "stepup_user_identifier": stepup_user_identifier,
            }
        )

        if not is_stepup_successful:
            error_context = {
                "message": "StepUp authentication failed",
                "issuer": issuer,
                "requester": requester,
                "stepup_provider": stepup_provider,
                "issuer_loa": issuer_loa,
                "requester_loas": requester_loas,
                "accepted_loas": accepted_loas,
                "required_loa": required_loa,
                "stepup_loa": stepup_loa,
                "is_stepup_provider": is_stepup_provider,
                "is_stepup_loa_exact": is_stepup_loa_exact,
                "is_subject_identified": is_subject_identified,
                "is_mfa_satisfied": is_mfa_satisfied,
                "is_stepup_successful": is_stepup_successful,
            }
            raise StepUpError(error_context)

        # the internal attribute that holds the assurances
        # XXX TODO make this configurable
        int_assurance_attribute_name = "edupersonassurance"
        # the SAML attribute that holds the assurances for this step-up provider/issuer
        stepup_assurance_attribute_name = linked_account.get("assurance", "eduPersonAssurance")
        # get the new assurances and add them
        stepup_assurances = authn_response.ava.get(stepup_assurance_attribute_name, [])
        data.attributes[int_assurance_attribute_name] = [
            *data.attributes.get(int_assurance_attribute_name, []),
            *stepup_assurances,
        ]

        data.auth_info.auth_class_ref = next(iter(requester_loas), stepup_loa)
        return super().process(context, data)

    def _metadata_endpoint(self, context):
        metadata_string = create_metadata_string(None, self.sp.config, 4, None, None, None, None, None).decode("utf-8")
        return Response(metadata_string, content="text/xml")

    def register_endpoints(self):
        url_map: List[Tuple[str, Callable]] = []

        # acs endpoints
        sp_endpoints = self.sp.config.getattr("endpoints", "sp")
        for endp, binding in sp_endpoints["assertion_consumer_service"]:
            parsed_endp = urlparse(endp)
            url_map.append(
                (
                    "^{endpoint}$".format(endpoint=parsed_endp.path[1:]),
                    functools.partial(self._handle_authn_response, binding=binding),
                )
            )

        # metadata endpoint
        parsed_entity_id = urlparse(self.sp.config.entityid)
        url_map.append(
            (
                "^{endpoint}".format(endpoint=parsed_entity_id.path[1:]),
                self._metadata_endpoint,
            )
        )

        return url_map
