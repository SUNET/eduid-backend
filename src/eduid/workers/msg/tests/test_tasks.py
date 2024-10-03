from unittest.mock import MagicMock, call, patch

import pytest
from celery.exceptions import Retry

from eduid.userdb.testing import SetupConfig
from eduid.workers.msg.testing import MsgMongoTestCase


class MockException(Exception):
    pass


class TestTasks(MsgMongoTestCase):
    def setUp(self, config: SetupConfig | None = None) -> None:
        super().setUp(config=config)

    @patch("smscom.SMSClient.send")
    def test_send_message_sms(self, sms_mock: MagicMock) -> None:
        sms_mock.return_value = True
        self.msg_relay.sendsms(recipient="+466666", message="foo", reference="ref")

        # Test that the content of the SMS matches the message above
        expected = [call("foo", "Test sender", "+466666", prio=2)]
        assert sms_mock.mock_calls == expected

    def test_send_message_sms_unused_range(self) -> None:
        # only tests that the numbers does not reach smscom, if smscom was called there would
        # be an authentication error (or network error if no internet connection)
        for i in range(5, 100):
            recipient = f"+467017406{str(i).zfill(2)}"
            self.msg_relay.sendsms(recipient=recipient, message="foo", reference="ref")

    def test_send_message_invalid_phone_number(self) -> None:
        with pytest.raises(Retry) as exc_info:
            self.msg_relay.sendsms(recipient="+466666a", message="foo", reference="ref")

        assert exc_info.value.excs == "ValueError(\"'to' is not a valid phone number\")"

    @patch("smscom.SMSClient.send")
    def test_send_message_sms_exception(self, sms_mock: MagicMock) -> None:
        """Test creating an artificial exception in the SMSClient.send"""
        sms_mock.side_effect = MockException("Unrecoverable error")
        with pytest.raises(Retry) as exc_info:
            self.msg_relay.sendsms(recipient="+466666", message="foo", reference="ref")
        assert exc_info.value.excs == "MockException('Unrecoverable error')"

    def test_ping(self) -> None:
        ret = self.msg_relay.ping()
        self.assertEqual(ret, "pong for testing")
