import json

import pytest
from celery.exceptions import Retry
from mock import MagicMock, call, patch

from eduid_msg.testing import MsgMongoTestCase
from eduid_msg.utils import load_template


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
        from eduid_msg.tasks import send_message

        sms_mock.return_value = True
        status = send_message.delay('sms', 'reference', self.msg_dict, '+466666', 'test.tmpl', 'sv_SE').get()

        # Test that the template was actually used in send_message function call to the sms service
        template = load_template(self.msg_settings.template_dir, 'test.tmpl', self.msg_dict, 'sv_SE')
        expected = [call(template.encode('utf-8'), 'Test sender', '+466666', prio=2)]
        self.assertEqual(sms_mock.mock_calls, expected)
        self.assertTrue(status)

    def test_send_message_invalid_phone_number(self):
        from eduid_msg.tasks import send_message

        with pytest.raises(Retry) as exc_info:
            send_message.delay('sms', 'reference', self.msg_dict, '+466666a', 'test.tmpl', 'sv_SE').get()

        assert exc_info.value.excs == 'ValueError("\'to\' is not a valid phone number")'

    @patch('smscom.SMSClient.send', side_effect=Exception('Unrecoverable error'))
    def test_send_message_sms_exception(self, sms_mock):
        from eduid_msg.tasks import send_message

        sms_mock.return_value = True
        with self.assertRaises(Exception):
            send_message.apply_async(args=['sms', 'reference', self.msg_dict, '+386666', 'test.tmpl', 'sv_SE'])

    @patch('eduid_msg.tasks.MessageRelay.mm_api')
    def test_is_reachable_cache(self, api_mock):
        from eduid_msg.tasks import is_reachable

        response = self.response()
        response.data = self.recipient_ok
        api_mock.user.reachable.POST.return_value = response
        status = is_reachable.delay('192705178354').get()
        self.assertTrue(status)
        mdb = self.tmp_db.conn['test']
        result = mdb['recipient_cache'].find_one({'identifier': '192705178354'})
        self.assertEqual(result['data']['SenderAccepted'], True)

    @patch('eduid_msg.tasks.MessageRelay.mm_api')
    def test_send_message_mm(self, api_mock):
        from eduid_msg.tasks import send_message

        reachable_response = self.response()
        reachable_response.data = self.recipient_ok
        api_mock.user.reachable.POST.return_value = reachable_response
        message_response = self.response()
        message_response.data = self.message_delivered
        api_mock.message.send.POST.return_value = message_response
        recipient = '192705178354'
        transaction_id = send_message.delay(
            'mm', 'reference', self.msg_dict, recipient, 'test.tmpl', 'sv_SE', subject='Test'
        ).get()
        self.assertEqual(transaction_id, 'ab6895f8-7203-4695-b083-ca89d68bf346')

        # Test that the template was actually used in send_message function call to the mm service
        template = load_template(self.msg_settings.template_dir, 'test.tmpl', self.msg_dict, 'sv_SE')
        reachable_data = json.dumps({"identity_number": recipient})
        message_data = json.dumps(
            {
                "recipient": recipient,
                "subject": "Test",
                "content_type": "text/html",
                "language": "svSE",
                "message": template,
            }
        )
        expected = [call.user.reachable.POST(data=reachable_data), call.message.send.POST(data=message_data)]
        self.assertEqual(api_mock.mock_calls, expected)

    @patch('eduid_msg.tasks.MessageRelay.mm_api')
    def test_send_message_mm_sender_not_accepted(self, api_mock):
        from eduid_msg.tasks import send_message

        reachable_response = self.response()
        reachable_response.data = self.recipient_sender_not
        api_mock.user.reachable.POST.return_value = reachable_response
        status = send_message.delay(
            'mm', 'reference', self.msg_dict, '192705178354', 'test.tmpl', 'sv_SE', subject='Test'
        ).get()
        self.assertEqual(status, "Sender_not")

    @patch('eduid_msg.tasks.MessageRelay.mm_api')
    def test_send_message_mm_recipient_not_existing(self, api_mock):
        from eduid_msg.tasks import send_message

        reachable_response = self.response()
        reachable_response.data = self.recipient_not
        api_mock.user.reachable.POST.return_value = reachable_response
        status = send_message.delay(
            'mm', 'reference', self.msg_dict, '192705178354', 'test.tmpl', 'sv_SE', subject='Test'
        ).get()
        self.assertEqual(status, None)

    @patch('eduid_msg.tasks.MessageRelay.mm_api')
    def test_send_message_mm_recipient_anonymous(self, api_mock):
        from eduid_msg.tasks import send_message

        reachable_response = self.response()
        reachable_response.data = self.recipient_anon
        api_mock.user.reachable.POST.return_value = reachable_response
        status = send_message.delay(
            'mm', 'reference', self.msg_dict, '192705178354', 'test.tmpl', 'sv_SE', subject='Test'
        ).get()
        self.assertEqual(status, "Anonymous")

    def test_ping(self):
        from eduid_msg.tasks import pong

        ret = pong.delay().get()
        self.assertEqual(ret, 'pong')
