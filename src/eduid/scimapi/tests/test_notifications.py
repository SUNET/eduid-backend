# -*- coding: utf-8 -*-

from unittest import SkipTest, mock
from uuid import uuid4

import boto3

# from moto import mock_sns

from eduid.scimapi.db.eventdb import EventLevel
from eduid.scimapi.models.scimbase import SCIMResourceType, SCIMSchema
from eduid.scimapi.testing import ScimApiTestCase
from eduid.scimapi.utils import make_etag

__author__ = 'lundberg'


# TODO: Try to setup a mock sqs to verify the published message

mock_sns = mock.MagicMock()  # fix import error for skipped tests


@SkipTest  # type: ignore
class TestNotifications(ScimApiTestCase):
    def setUp(self) -> None:
        super().setUp()

    def _get_config(self) -> dict:
        config = super()._get_config()
        config.update(
            {'aws_access_key_id': 'some_key', 'aws_secret_access_key': 'some_secret_key', 'aws_region': 'eu-north-1'}
        )
        config['data_owners']['eduid.se']['notify'] = ['arn:aws:sns:eu-north-1:123456789012:mock-topic']
        return config

    @mock_sns
    def test_create_user_notification(self):
        # Setup mock topic to publish to
        sns_client = boto3.client('sns', region_name=self.context.config.aws_region)
        sns_client.create_topic(Name='mock-topic')

        req = {'schemas': [SCIMSchema.CORE_20_USER.value], 'externalId': 'test-id-1'}
        response = self.client.post(url='/Users/', data=self.as_json(req), headers=self.headers)
        self._assertResponse(response, status_code=201)

    @mock_sns
    def test_create_group_notification(self):
        # Setup mock topic to publish to
        sns_client = boto3.client('sns', region_name=self.context.config.aws_region)
        sns_client.create_topic(Name='mock-topic')

        req = {'schemas': [SCIMSchema.CORE_20_GROUP.value], 'externalId': 'test-id-1', 'displayName': 'Test Group'}
        response = self.client.post(url='/Groups/', data=self.as_json(req), headers=self.headers)
        self._assertResponse(response, status_code=201)

    @mock_sns
    def test_create_event_notification(self):
        # Setup mock topic to publish to
        sns_client = boto3.client('sns', region_name=self.context.config.aws_region)
        sns_client.create_topic(Name='mock-topic')

        user = self.add_user(identifier=str(uuid4()), external_id='test@example.org')
        event = {
            'resource': {
                'resourceType': SCIMResourceType.USER.value,
                'id': str(user.scim_id),
                'version': make_etag(user.version),
                'lastModified': str(user.last_modified),
            },
            'level': EventLevel.ERROR.value,
            'data': {'create_test': True},
        }
        req = {'schemas': [SCIMSchema.NUTID_EVENT_V1.value], SCIMSchema.NUTID_EVENT_V1.value: event}
        result = self.client.post(url='/Events/', data=self.as_json(req), headers=self.headers)
        self._assertResponse(result)
