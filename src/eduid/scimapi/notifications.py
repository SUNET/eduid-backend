# -*- coding: utf-8 -*-
__author__ = 'lundberg'

import json
import logging
from typing import Any, Dict, List

import boto3

from eduid.scimapi.config import ScimApiConfig

logger = logging.getLogger(__name__)


class NotificationRelay:
    def __init__(self, config: ScimApiConfig):
        self.config = config
        self.sns_client = None
        if config.aws_access_key_id and config.aws_secret_access_key and config.aws_region:
            boto3.setup_default_session(
                aws_access_key_id=config.aws_access_key_id,
                aws_secret_access_key=config.aws_secret_access_key,
                region_name=config.aws_region,
            )
            self.sns_client = boto3.client('sns')

    def _topics_for(self, data_owner: str) -> List[str]:
        if data_owner not in self.config.data_owners:
            return []
        return self.config.data_owners[data_owner].notify

    def format_message(self, version: int, data: Dict[str, Any]):
        if version != 1:
            raise NotImplementedError(f'version {version} not implemented')
        return json.dumps({'v': version, 'location': data['location']})

    def notify(self, data_owner: str, message: str) -> None:
        if self.sns_client is not None:
            logger.info(f'Notifying {data_owner}')
            logger.debug(f'message: {message}')
            for topic_arn in self._topics_for(data_owner):
                logger.debug(f'TopicArn: {topic_arn}')
                res = self.sns_client.publish(TopicArn=topic_arn, Message=message)
                logger.debug(f'Publish result: {res}')


# FT_TEST_ARN = 'arn:aws:sns:eu-north-1:075581119103:ft-test'
# parsed_response = sns_client.list_subscriptions_by_topic(TopicArn=FT_TEST_ARN,)
# print(f'Subscribers: {pprint.pformat(parsed_response)}')
# res = {
#     'MessageId': '811d328f-b633-5fa3-aab4-6a0f4ab56f94',
#     'ResponseMetadata': {
#         'RequestId': '772ad819-a85b-5c54-85e2-809954dd3c63',
#         'HTTPStatusCode': 200,
#         'HTTPHeaders': {
#             'x-amzn-requestid': '772ad819-a85b-5c54-85e2-809954dd3c63',
#             'content-type': 'text/xml',
#             'content-length': '294',
#             'date': 'Tue, 19 Jan 2021 15:27:01 GMT',
#         },
#         'RetryAttempts': 0,
#     },
# }
