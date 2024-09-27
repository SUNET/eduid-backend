from unittest.mock import MagicMock, call, patch

import pytest
from celery.exceptions import Retry

from eduid.userdb.user import User
from eduid.workers.msg.testing import MsgMongoTestCase


class MockException(Exception):
    pass


class TestTasks(MsgMongoTestCase):
    def setUp(self, am_users: list[User] | None = None, init_msg: bool = True):
        super().setUp(init_msg=init_msg)
        self.msg_dict = {"name": "Godiskungen", "admin": "Testadmin"}

        class APIResponse(MagicMock):
            status_code = 200

            def json(self):
                return self.data

        self.response = APIResponse

        self.recipient_ok = {
            "AccountStatus": {
                "RecipientId": "192705178354",
                "ServiceSupplier": {"ServiceAddress": "https://notarealhost.skatteverket.se/webservice/accao/Service"},
                "Type": "Secure",
            },
            "SenderAccepted": True,
        }

        self.recipient_sender_not = {
            "AccountStatus": {
                "RecipientId": "192705178354",
                "ServiceSupplier": {"ServiceAddress": "https://notarealhost.skatteverket.se/webservice/accao/Service"},
                "Type": "Secure",
            },
            "SenderAccepted": False,
        }

        self.recipient_not = {
            "AccountStatus": {
                "RecipientId": "192705178354",
                "ServiceSupplier": {"ServiceAddress": "https://notarealhost.skatteverket.se/webservice/accao/Service"},
                "Type": "Not",
            },
            "SenderAccepted": False,
        }

        self.recipient_anon = {
            "AccountStatus": {
                "RecipientId": "192705178354",
                "ServiceSupplier": {"ServiceAddress": "https://notarealhost.skatteverket.se/webservice/accao/Service"},
                "Type": "Anonymous",
            },
            "SenderAccepted": True,
        }

        self.message_delivered = {
            "delivered": True,
            "recipient": "192705178354",
            "transaction_id": "ab6895f8-7203-4695-b083-ca89d68bf346",
        }

    @patch("smscom.SMSClient.send")
    def test_send_message_sms(self, sms_mock: MagicMock):
        sms_mock.return_value = True
        self.msg_relay.sendsms(recipient="+466666", message="foo", reference="ref")

        # Test that the content of the SMS matches the message above
        expected = [call("foo", "Test sender", "+466666", prio=2)]
        assert sms_mock.mock_calls == expected

    def test_send_message_sms_unused_range(self):
        # only tests that the numbers does not reach smscom, if smscom was called there would
        # be an authentication error (or network error if no internet connection)
        for i in range(5, 100):
            recipient = f"+467017406{str(i).zfill(2)}"
            self.msg_relay.sendsms(recipient=recipient, message="foo", reference="ref")

    def test_send_message_invalid_phone_number(self):
        with pytest.raises(Retry) as exc_info:
            self.msg_relay.sendsms(recipient="+466666a", message="foo", reference="ref")

        assert exc_info.value.excs == "ValueError(\"'to' is not a valid phone number\")"

    @patch("smscom.SMSClient.send")
    def test_send_message_sms_exception(self, sms_mock: MagicMock):
        """Test creating an artificial exception in the SMSClient.send"""
        sms_mock.side_effect = MockException("Unrecoverable error")
        with pytest.raises(Retry) as exc_info:
            self.msg_relay.sendsms(recipient="+466666", message="foo", reference="ref")
        assert exc_info.value.excs == "MockException('Unrecoverable error')"

    def test_ping(self):
        ret = self.msg_relay.ping()
        self.assertEqual(ret, "pong for testing")
