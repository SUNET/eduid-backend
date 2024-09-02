import logging
import re
from typing import Any, Mapping

import satosa.internal
from satosa.micro_services.base import ResponseMicroService

from eduid.common.config.base import StatsConfigMixin
from eduid.common.stats import init_app_stats

logger = logging.getLogger(__name__)


class requester_counter(ResponseMicroService):
    """
        A class to count the requesting SP.

        Example configuration:
    ```yaml
        module: statsd.requester_counter
        name: requester_counter
        config:
                app_name: idpproxy
                stats_port: 8125
                stats_host': monitor-fre-1.eduid.se

    ```
    """

    def __init__(self, config: Mapping[str, Any], *args: Any, **kwargs: Any):

        super().__init__(*args, **kwargs)

        statsd_config = StatsConfigMixin(**config)
        self.stats = init_app_stats(statsd_config)

    def process(
        self, context: satosa.context.Context, data: satosa.internal.InternalData
    ) -> satosa.internal.InternalData:
        requester_entity_id = data.requester
        if not requester_entity_id:
            logger.warn("Unable to determine the entityID for the SP requester")
            return super().process(context, data)

        # Graphite is picky about the characters in it's key names
        requester_entity_id = re.sub(r"[^a-zA-Z0-9]", "_", requester_entity_id)
        # For easier readability - only allow one underscore in a row
        requester_entity_id = re.sub(r"_{2,}", "_", requester_entity_id)

        graphite_key = f"requester.{requester_entity_id}"

        logger.debug(f"Counting {graphite_key}")
        self.stats.count(graphite_key)

        return super().process(context, data)
