import logging
from dataclasses import field
from typing import Any, Mapping, Optional, Union

import satosa.internal
from satosa.context import Context
from satosa.exception import SATOSAAuthenticationError, SATOSAConfigurationError
from satosa.micro_services.base import RequestMicroService, ResponseMicroService

logger = logging.getLogger(__name__)


SupportedACCRsSortedByPrioConfig = list[str]
LowestAcceptedACCRForVirtualIdpConfig = dict[str, str]
InternalACCRRewriteMap: Mapping[str, str] = field(default_factory=dict)
ProcessReturnType = Union[satosa.internal.InternalData, satosa.response.Response]


class request(RequestMicroService):
    """
    A class to handle and the ACCR request flowing through Satosa.
    ```yaml
    module: eduid.satosa.scimapi.accr.request
    name: accrRequest
    config:
        supported_accr_sorted_by_prio:
            - https://refeds.org/profile/mfa
            - https://refeds.org/profile/sfa
            - urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
        lowest_accepted_accr_for_virtual_idp:
            SunetIDP: https://refeds.org/profile/mfa
        internal_accr_rewrite_map:
            http://id.swedenconnect.se/loa/1.0/uncertified-loa2: http://id.elegnamnden.se/loa/1.0/loa2
    """

    def __init__(self, config: Mapping[str, Any], internal_attributes: dict[str, Any], *args: Any, **kwargs: Any):
        self.lowest_accepted_accr_for_virtual_idp: Optional[LowestAcceptedACCRForVirtualIdpConfig] = config.get(
            "lowest_accepted_accr_for_virtual_idp"
        )
        self.supported_accr_sorted_by_prio: SupportedACCRsSortedByPrioConfig = config.get(
            "supported_accr_sorted_by_prio", []
        )
        self.internal_accr_rewrite_map: Optional[SupportedACCRsSortedByPrioConfig] = config.get(
            "internal_accr_rewrite_map"
        )

        super().__init__(*args, **kwargs)

    def process(self, context: satosa.context.Context, data: satosa.internal.InternalData) -> ProcessReturnType:
        requested_accr: list[str] = context.get_decoration(Context.KEY_AUTHN_CONTEXT_CLASS_REF)

        if requested_accr:
            supported_accr_to_forward = []
            for accr in requested_accr:
                if accr in self.supported_accr_sorted_by_prio:
                    supported_accr_to_forward.append(accr)
                else:
                    logger.debug(f"Removing unsupported ACCR ({accr}) from request")

            if not supported_accr_to_forward:
                raise SATOSAAuthenticationError(context.state, "Unsupported ACCR")
            else:
                requested_accr = supported_accr_to_forward

        internal_accr_rewrite_map = self.internal_accr_rewrite_map
        if internal_accr_rewrite_map and requested_accr:
            context.state["internal_accr_rewrite_map"] = internal_accr_rewrite_map
            for index, value in enumerate(requested_accr):
                if value in internal_accr_rewrite_map:
                    logger.debug(f"Remapping ACCR for internal use. From {value} to {internal_accr_rewrite_map[value]}")
                    requested_accr[index] = internal_accr_rewrite_map[value]

        context.state["saved_accr"] = requested_accr
        context.state["supported_accr_sorted_by_prio"] = self.supported_accr_sorted_by_prio
        accr_to_forward = requested_accr
        logger.debug(f"Saving requested ACCR for later use: {requested_accr}).")

        virtual_idp = context.target_frontend
        if self.lowest_accepted_accr_for_virtual_idp:
            minimum_accr = self.lowest_accepted_accr_for_virtual_idp.get(virtual_idp)
        if minimum_accr:
            logger.debug(f"Minimum accepted ACCR for {virtual_idp} is: {minimum_accr}.")
            supported_accr = self.supported_accr_sorted_by_prio
            if minimum_accr in supported_accr:
                required_accr_by_virtual_idp = supported_accr[: supported_accr.index(minimum_accr) + 1]
            else:
                # XXX - This should probably be done in __init__ when configuration is loaded.
                raise SATOSAConfigurationError(
                    f"Required ACCR ({minimum_accr}) not present in supported ACCR(s) ({supported_accr})"
                )

            logger.debug(
                f"Replacing requested ACCR: {requested_accr}, with what {virtual_idp} requires: {required_accr_by_virtual_idp}."
            )
            accr_to_forward = required_accr_by_virtual_idp

        context.state[Context.KEY_TARGET_AUTHN_CONTEXT_CLASS_REF] = accr_to_forward

        return super().process(context, data)


class response(ResponseMicroService):
    """
    A class to handle and the ACCR response flowing through Satosa.
    ```yaml
    module: eduid.satosa.scimapi.accr.response
    name: accrResponse
    """

    def __init__(self, config: Mapping[str, Any], internal_attributes: dict[str, Any], *args: Any, **kwargs: Any):

        super().__init__(*args, **kwargs)

    def process(self, context: satosa.context.Context, data: satosa.internal.InternalData) -> ProcessReturnType:
        received_accr = data.auth_info.auth_class_ref
        saved_accr = context.state.get("saved_accr")
        internal_accr_rewrite_map = context.state.get("internal_accr_rewrite_map")
        supported_accr_sorted_by_prio = context.state.get("supported_accr_sorted_by_prio")
        logger.debug(f"Received ACCR from IdP: {received_accr}")
        logger.debug(f"Saved (requested) ACCR from state: {saved_accr}")

        if internal_accr_rewrite_map and received_accr:
            for origin, rewrite in internal_accr_rewrite_map.items():
                if received_accr == rewrite:
                    logger.debug(f"Rewriting ACCR {received_accr} back to {origin}")
                    received_accr = origin
                    break

        if not saved_accr:
            logger.debug(f"No ACCR in request, setting: {received_accr}")
            data.auth_info.auth_class_ref = received_accr
        else:
            for accr in supported_accr_sorted_by_prio:
                if accr in saved_accr:
                    logger.debug(f"Setting ACCR to most priorirtied avaliable value in request: {accr}")
                    data.auth_info.auth_class_ref = accr
                    break
            # XXX exception if no match?

        return super().process(context, data)
