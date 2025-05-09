import logging
import uuid
from collections.abc import Mapping
from typing import Any, TypeAlias

import satosa.internal
import satosa.response
from saml2.saml import (
    NAMEID_FORMAT_EMAILADDRESS,
    NAMEID_FORMAT_PERSISTENT,
    NAMEID_FORMAT_TRANSIENT,
    NAMEID_FORMAT_UNSPECIFIED,
)
from satosa.exception import SATOSAAuthenticationError
from satosa.micro_services.base import RequestMicroService, ResponseMicroService

logger = logging.getLogger(__name__)
ProcessReturnType: TypeAlias = satosa.internal.InternalData | satosa.response.Response
ALLOWED_NAMEIDS = (
    NAMEID_FORMAT_UNSPECIFIED,
    NAMEID_FORMAT_EMAILADDRESS,
    NAMEID_FORMAT_PERSISTENT,
    NAMEID_FORMAT_TRANSIENT,
)


class request(RequestMicroService):
    def __init__(
        self,
        config: Mapping[str, Any],
        internal_attributes: dict[str, Any],
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)

    def process(self, context: satosa.context.Context, data: satosa.internal.InternalData) -> ProcessReturnType:
        # Pysaml or satosa makes sure that we always have a subject_typeeven
        # even if not requested by the SP or specified in the metadata.
        if data.subject_type:
            if data.subject_type not in ALLOWED_NAMEIDS:
                # Handle unsupported NameIDs as NAMEID_FORMAT_TRANSIENT for compability.
                logger.info(
                    f"Requested NameID ({data.subject_type}) is not supported, changing it to {NAMEID_FORMAT_TRANSIENT}"
                )
                data.subject_type = NAMEID_FORMAT_TRANSIENT
        else:
            raise SATOSAAuthenticationError(context.state, "No NameID")

        logger.info(f"Saving requested NameID for later use: {data.subject_type}")
        context.state["subject_type"] = data.subject_type

        return super().process(context, data)


class response(ResponseMicroService):
    def __init__(
        self,
        config: Mapping[str, Any],
        internal_attributes: dict[str, Any],
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)

    def process(self, context: satosa.context.Context, data: satosa.internal.InternalData) -> ProcessReturnType:
        subject_type = context.state.get("subject_type")
        if not subject_type:
            raise SATOSAAuthenticationError(context.state, "No NameID from saved state")

        logger.info(f"Requested (by SP) NameID type from state: {subject_type}")

        if subject_type == NAMEID_FORMAT_TRANSIENT or subject_type == NAMEID_FORMAT_UNSPECIFIED:
            data.subject_id = str(uuid.uuid1())
            data.subject_type = NAMEID_FORMAT_TRANSIENT
        elif subject_type == NAMEID_FORMAT_PERSISTENT:
            pairwise = data.attributes.get("pairwise-id")[0]
            if not pairwise:
                raise SATOSAAuthenticationError(context.state, "No pairwise ID to use as persistant NameID")
            data.subject_id = pairwise.split("@")[0]
            data.subject_type = subject_type
        elif subject_type == NAMEID_FORMAT_EMAILADDRESS:
            mail = data.attributes.get("mail")[0]
            if not mail:
                raise SATOSAAuthenticationError(context.state, "No mail to use as NameID")
            data.subject_id = mail
            data.subject_type = subject_type
        else:
            # This should not even be possible
            raise SATOSAAuthenticationError(context.state, "Unknown NameID")

        logger.debug(f"Returning NameID ({subject_type}): {data.subject_id}")
        return super().process(context, data)
