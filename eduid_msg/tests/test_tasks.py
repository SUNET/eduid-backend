from mock import patch, call
from eduid_msg.tests import MongoTestCase
from eduid_msg.celery import celery, get_message_relay
from eduid_msg.tasks import send_message, is_reachable
from eduid_msg.utils import load_template
import pkg_resources


class TestTasks(MongoTestCase):
    def setUp(self):
        super(TestTasks, self).setUp()
        data_dir = pkg_resources.resource_filename(__name__, 'data')
        settings = {
            'BROKER_TRANSPORT': 'memory',
            'BROKER_URL': 'memory://',
            'CELERY_EAGER_PROPAGATES_EXCEPTIONS': True,
            'CELERY_ALWAYS_EAGER': True,
            'CELERY_RESULT_BACKEND': "cache",
            'CELERY_CACHE_BACKEND': 'memory',
            'MONGO_URI': 'mongodb://localhost:%d/' % self.port,
            'MONGO_DBNAME': 'test',
            'CACHE_REACHABLE': 'test',
            'SMS_ACC': 'foo',
            'SMS_KEY': 'bar',
            'SMS_SENDER': 'Test sender',
            'MM_DEFAULT_SUBJECT': 'Test case',
            'MM_SENDER_ORG_NR': '1234567',
            'TEMPLATE_DIR': data_dir,
        }
        celery.conf.update(settings)
        self.msg_dict = {
            'name': 'Godiskungen',
            'admin': 'Testadmin'
        }

    @patch('smscom.SMSClient.send')
    def test_send_message_sms(self, sms_mock):
        sms_mock.return_value = True
        status = send_message.delay('sms', self.msg_dict, '+466666', 'test.tmpl', 'sv_SE').get()

        # Test that the template was actually used in send_message function call to the sms service
        template = load_template(celery.conf.get('TEMPLATE_DIR'), 'test.tmpl', 'sv_SE')
        expected = [call(template.format(**self.msg_dict), 'Test sender', '+466666', prio=2)]
        self.assertEqual(sms_mock.mock_calls, expected)
        self.assertTrue(status)

    def test_send_message_invalid_phone_number(self):
        try:
            send_message.delay('sms', self.msg_dict, '+466666a', 'test.tmpl', 'sv_SE').get()
        except ValueError, e:
            self.assertEqual(e.message, "'to' is not a valid phone number")

    @patch('eduid_msg.tasks.MessageRelay.recipient')
    def test_is_reachable_cache(self, recipient_mock):
        recipient_mock.is_reachable.return_value = [{'SenderAccepted': True, 'test': 'test', 'test2': 'cookies'}]
        status = is_reachable.delay('192705178354').get()
        self.assertTrue(status)
        mr = get_message_relay(celery)
        mdb = mr.cache
        result = mdb.collection.find_one({'identifier': '192705178354'})
        self.assertEqual(result['data']['test2'], 'cookies')

    @patch('eduid_msg.tasks.MessageRelay.recipient')
    @patch('eduid_msg.tasks.MessageRelay.message')
    def test_send_message_mm(self, message_mock, recipient_mock):
        recipient_mock.is_reachable.return_value = [{'SenderAccepted': True, 'test': 'test', 'test2': 'cookies'}]
        message_mock.create_secure_message.return_value = True
        message_mock.send_secure_messsage.return_value = True
        message_mock.check_distribution_status.return_value = [{'DeliveryStatus': 'Delivered', 'Type': 'Digital', 'RecipientId': '192705178354'}]
        status = send_message.delay('mm', self.msg_dict, '+466666', 'test.tmpl', 'sv_SE', subject='Test').get()
        self.assertEqual(status['RecipientId'], '192705178354')

        # Test that the template was actually used in send_message function call to the mm service
        template = load_template(celery.conf.get('TEMPLATE_DIR'), 'test.tmpl', 'sv_SE')
        expected = call.create_secure_message('Test', template.format(**self.msg_dict), 'text/plain', 'svSE')
        self.assertEqual(message_mock.mock_calls[0], expected)

        # Testing failed delivery
        message_mock.check_distribution_status.return_value = [{'DeliveryStatus': 'DeliveryFailed', 'Type': 'Digital', 'RecipientId': '192705178354'}]
        status = send_message.delay('mm', self.msg_dict, '+466666', 'test.tmpl', 'sv_SE', subject='Test').get()
        self.assertEqual(status['DeliveryStatus'], 'DeliveryFailed')
