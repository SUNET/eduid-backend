# -*- coding: utf-8 -*-

from eduid_scimapi.testing import ScimApiTestCase

__author__ = 'lundberg'


class TestNotificationLogging(ScimApiTestCase):
    def setUp(self) -> None:
        super().setUp()
        # Headers and body from AWS documentation
        self.headers = {
            'x-amz-sns-message-type': 'Notification',
            'x-amz-sns-message-id': 'da41e39f-ea4d-435a-b922-c6aae3915ebe',
            'x-amz-sns-topic-arn': 'arn:aws:sns:us-west-2:123456789012:MyTopic',
            'x-amz-sns-subscription-arn': 'arn:aws:sns:us-west-2:123456789012:MyTopic:2bcfbf39-05c3-41de-beaa-fcfcc21c8f55',
            'Content-Type': 'text/plain; charset=UTF-8',
        }
        self.body = {
            'Type': 'Notification',
            'MessageId': 'da41e39f-ea4d-435a-b922-c6aae3915ebe',
            'TopicArn': 'arn:aws:sns:us-west-2:123456789012:MyTopic',
            'Subject': 'test',
            'Message': 'test message',
            'Timestamp': '2012-04-25T21:49:25.719Z',
            'SignatureVersion': '1',
            'Signature': 'EXAMPLElDMXvB8r9R83tGoNn0ecwd5UjllzsvSvbItzfaMpN2nk5HVSw7XnOn/49IkxDKz8YrlH2qJXj2iZB0Zo2O71c4qQk1fMUDi3LGpij7RCW7AW9vYYsSqIKRnFS94ilu7NFhUzLiieYr4BKHpdTmdD6c0esKEYBpabxDSc=',
            'SigningCertURL': 'https://sns.us-west-2.amazonaws.com/SimpleNotificationService-f3ecfb7224c7233fe7bb5f59f96de52f.pem',
            'UnsubscribeURL': 'https://sns.us-west-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-west-2:123456789012:MyTopic:2bcfbf39-05c3-41de-beaa-fcfcc21c8f55',
        }

    def test_post_notification(self):
        response = self.client.simulate_post(path='/notifications', headers=self.headers, body=self.as_json(self.body))
        assert response.status_code == 200
