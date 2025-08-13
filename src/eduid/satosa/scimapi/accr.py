import logging
from collections.abc import Mapping
from copy import deepcopy
from typing import Any

import satosa.internal
import satosa.response
from satosa.context import Context
from satosa.exception import SATOSAAuthenticationError, SATOSAConfigurationError
from satosa.micro_services.base import RequestMicroService, ResponseMicroService

logger = logging.getLogger(__name__)


SupportedACCRsSortedByPrioConfig = list[str]
LowestAcceptedACCRForVirtualIdpConfig = dict[str, str]
InternalACCRRewriteMap = Mapping[str, str]
type ProcessReturnType = satosa.internal.InternalData | satosa.response.Response


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

    def __init__(
        self, config: Mapping[str, Any], internal_attributes: dict[str, Any], *args: Any, **kwargs: Any
    ) -> None:
        self.lowest_accepted_accr_for_virtual_idp: LowestAcceptedACCRForVirtualIdpConfig | None = config.get(
            "lowest_accepted_accr_for_virtual_idp"
        )
        self.supported_accr_sorted_by_prio: SupportedACCRsSortedByPrioConfig = config.get(
            "supported_accr_sorted_by_prio", []
        )
        self.internal_accr_rewrite_map: InternalACCRRewriteMap | None = config.get("internal_accr_rewrite_map")

        if self.lowest_accepted_accr_for_virtual_idp:
            for idp, minimum_accr in self.lowest_accepted_accr_for_virtual_idp.items():
                if minimum_accr not in self.supported_accr_sorted_by_prio:
                    raise SATOSAConfigurationError(
                        f"{idp} has minium required accr {minimum_accr} not in supported accrs"
                    )

        super().__init__(*args, **kwargs)

    def process(self, context: satosa.context.Context, data: satosa.internal.InternalData) -> ProcessReturnType:
        requested_accr: list[str] = context.get_decoration(Context.KEY_AUTHN_CONTEXT_CLASS_REF)

        logger.debug(f"Incoming ACCR: {requested_accr}")
        supported_accr_to_forward = []
        if requested_accr:
            for accr in requested_accr:
                if accr in self.supported_accr_sorted_by_prio:
                    supported_accr_to_forward.append(accr)
                else:
                    logger.info(f"Removing unsupported ACCR ({accr}) from request")

            if not supported_accr_to_forward:
                raise SATOSAAuthenticationError(context.state, "Unsupported ACCR")

            requested_accr = deepcopy(supported_accr_to_forward)

        logger.info(f"Saving requested ACCR for later use: {requested_accr}).")
        context.state["requested_accr"] = requested_accr

        internal_accr_rewrite_map = self.internal_accr_rewrite_map
        if internal_accr_rewrite_map and supported_accr_to_forward:
            context.state["internal_accr_rewrite_map"] = internal_accr_rewrite_map
            for index, value in enumerate(supported_accr_to_forward):
                if value in internal_accr_rewrite_map:
                    logger.info(f"Remapping ACCR for internal use. From {value} to {internal_accr_rewrite_map[value]}")
                    supported_accr_to_forward[index] = internal_accr_rewrite_map[value]

        context.state["supported_accr_sorted_by_prio"] = self.supported_accr_sorted_by_prio
        accr_to_forward = supported_accr_to_forward

        virtual_idp = context.target_frontend
        minimum_accr = ""
        if self.lowest_accepted_accr_for_virtual_idp:
            minimum_accr = self.lowest_accepted_accr_for_virtual_idp.get(virtual_idp, "")
        if minimum_accr:
            logger.info(f"Minimum accepted ACCR for {virtual_idp} is: {minimum_accr}.")
            supported_accr = self.supported_accr_sorted_by_prio
            required_accr_by_virtual_idp = supported_accr[: supported_accr.index(minimum_accr) + 1]
            logger.info(
                f"Replacing requested ACCR: {requested_accr}, "
                f"with what {virtual_idp} requires: {required_accr_by_virtual_idp}."
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

    def __init__(
        self, config: Mapping[str, Any], internal_attributes: dict[str, Any], *args: Any, **kwargs: Any
    ) -> None:
        super().__init__(*args, **kwargs)

    def process(self, context: satosa.context.Context, data: satosa.internal.InternalData) -> ProcessReturnType:
        received_accr = data.auth_info.auth_class_ref
        requested_accr = context.state.get("requested_accr")
        internal_accr_rewrite_map = context.state.get("internal_accr_rewrite_map")
        supported_accr_sorted_by_prio = context.state.get("supported_accr_sorted_by_prio")
        logger.info(f"Received ACCR from IdP: {received_accr}")
        logger.info(f"Requested (by SP) ACCR from state: {requested_accr}")

        if internal_accr_rewrite_map and received_accr:
            for origin, rewrite in internal_accr_rewrite_map.items():
                if received_accr == rewrite:
                    logger.info(f"Rewriting ACCR {received_accr} back to {origin}")
                    received_accr = origin
                    break

        if received_accr not in requested_accr:
            for accr in supported_accr_sorted_by_prio:
                if accr in requested_accr:
                    logger.info(f"Setting ACCR to most prioritized available value in request: {accr}")
                    data.auth_info.auth_class_ref = accr
                    break
        else:
            data.auth_info.auth_class_ref = received_accr

        logger.info(f"Returing ACCR to SP: {data.auth_info.auth_class_ref}")

        return super().process(context, data)
