import pytest
from celery.exceptions import Retry
from mock import MagicMock, call, patch

from eduid.workers.msg.testing import MsgMongoTestCase


class MockException(Exception):
    pass


class TestTasks(MsgMongoTestCase):
    def setUp(self, init_msg=True):
        super(TestTasks, self).setUp(init_msg=init_msg)
        self.msg_dict = {'name': 'Godiskungen', 'admin': 'Testadmin'}

        class APIResponse(MagicMock):
            status_code = 200

            def json(self):
                return self.data

        self.response = APIResponse

        self.recipient_ok = {
            u'AccountStatus': {
                u'RecipientId': u'192705178354',
                u'ServiceSupplier': {
                    u'ServiceAddress': u'https://notarealhost.skatteverket.se/webservice/accao/Service'
                },
                u'Type': u'Secure',
            },
            u'SenderAccepted': True,
        }

        self.recipient_sender_not = {
            u'AccountStatus': {
                u'RecipientId': u'192705178354',
                u'ServiceSupplier': {
                    u'ServiceAddress': u'https://notarealhost.skatteverket.se/webservice/accao/Service'
                },
                u'Type': u'Secure',
            },
            u'SenderAccepted': False,
        }

        self.recipient_not = {
            u'AccountStatus': {
                u'RecipientId': u'192705178354',
                u'ServiceSupplier': {
                    u'ServiceAddress': u'https://notarealhost.skatteverket.se/webservice/accao/Service'
                },
                u'Type': u'Not',
            },
            u'SenderAccepted': False,
        }

        self.recipient_anon = {
            u'AccountStatus': {
                u'RecipientId': u'192705178354',
                u'ServiceSupplier': {
                    u'ServiceAddress': u'https://notarealhost.skatteverket.se/webservice/accao/Service'
                },
                u'Type': u'Anonymous',
            },
            u'SenderAccepted': True,
        }

        self.message_delivered = {
            u'delivered': True,
            u'recipient': u'192705178354',
            u'transaction_id': u'ab6895f8-7203-4695-b083-ca89d68bf346',
        }

    @patch('smscom.SMSClient.send')
    def test_send_message_sms(self, sms_mock):
        sms_mock.return_value = True
        self.msg_relay.sendsms(recipient='+466666', message='foo', reference='ref')

        # Test that the content of the SMS matches the message above
        expected = [call('foo', 'Test sender', '+466666', prio=2)]
        assert sms_mock.mock_calls == expected

    def test_send_message_invalid_phone_number(self):
        with pytest.raises(Retry) as exc_info:
            self.msg_relay.sendsms(recipient='+466666a', message='foo', reference='ref')

        assert exc_info.value.excs == 'ValueError("\'to\' is not a valid phone number")'

    @patch('smscom.SMSClient.send', )
    def test_send_message_sms_exception(self, sms_mock):
        """ Test creating an artificial exception in the SMSClient.send """
        sms_mock.side_effect = MockException('Unrecoverable error')
        with pytest.raises(Retry) as exc_info:
            self.msg_relay.sendsms(recipient='+466666', message='foo', reference='ref')
        assert exc_info.value.excs == "MockException('Unrecoverable error')"

    def test_ping(self):
        ret = self.msg_relay.ping()
        self.assertEqual(ret, 'pong')
