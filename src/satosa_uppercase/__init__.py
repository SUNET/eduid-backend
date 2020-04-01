import logging
import pprint

import satosa.context
import satosa.internal
from satosa.micro_services.base import ResponseMicroService

logger = logging.getLogger(__name__)


class UppercaseAttributes(ResponseMicroService):
    """
    Add static attributes to the responses.
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config
        logger.info(f'Uppercase module starting with configuration: {config}')

    def process(
        self, context: satosa.context.Context, data: satosa.internal.InternalData,
    ) -> satosa.internal.InternalData:
        logger.debug(f'Data as dict:\n{pprint.pformat(data.to_dict())}')

        for this in data.attributes:
            if this in self.config['attributes']:
                logger.info(f'Uppercasing attribute {this}, value {data.attributes[this]}')
                if isinstance(data.attributes[this], list):
                    data.attributes[this] = [x.upper() for x in data.attributes[this]]
                else:
                    data.attributes[this] = data.attributes[this].upper()
            else:
                logger.debug(f'Skipping attribute {this}')

        return super().process(context, data)
