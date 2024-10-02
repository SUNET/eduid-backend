import hmac
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

import satosa.context
import satosa.internal
from satosa.micro_services.base import ResponseMicroService

logger = logging.getLogger(__name__)


@dataclass
class Config:
    pairwise_salt: str


class GeneratePairwiseId(ResponseMicroService):
    """
    MicroService go generate pairwise-id based on subject-id

    Example configuration:

        module: eduid.satosa.scimapi.pairwiseid.GeneratePairwiseId
        plugin: GeneratePairwiseId
        name: GeneratePairwiseId
        config:
                pairwise_salt: chatroom-chemo-rethink-scarecrow-embark-truck

    """

    def __init__(
        self,
        config: Mapping[str, Any],
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.config = Config(**config)
        logger.info("Loaded pairwise-id generator")

    def process(
        self,
        context: satosa.context.Context,
        data: satosa.internal.InternalData,
    ) -> satosa.internal.InternalData:
        relying_party: str = data.requester
        subject_id: str = data.attributes.get("subject-id")[0]
        user_scope: str = subject_id.split("@")[-1]

        sp_user_id: str = f"{relying_party}-{subject_id}"
        pairwise_hash: str = hmac.new(
            bytes(self.config.pairwise_salt, "ascii"),
            msg=bytes(sp_user_id, "ascii"),
            digestmod=sha256,
        ).hexdigest()

        logger.debug(f"Pairwise-id for {subject_id} and {relying_party}: {pairwise_hash}@{user_scope}")
        data.attributes["pairwise-id"] = f"{pairwise_hash}@{user_scope}"

        return super().process(context, data)
