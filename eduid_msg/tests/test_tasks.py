from mock import patch, call
from eduid_msg.tests import MongoTestCase
from eduid_msg.celery import celery


class FakeDecorator(object):
    def __init__(self, uri):
        pass

    def __call__(self, f):
        def inner(*args, **kwargs):
            return f(*args, **kwargs)
        return inner

patch('eduid_msg.decorators.TransactionAudit', FakeDecorator).start()
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
            'SMS_ACC': 'foo',
            'SMS_KEY': 'bar',
            'SMS_SENDER': 'Test sender',
            'MM_DEFAULT_SUBJECT': 'Test case',
            'MM_SENDER_ORG_NR': '1234567',
            'TEMPLATE_DIR': data_dir,
            'MESSAGE_RATE_LIMIT': '2/m',
        }
        celery.conf.update(settings)
        self.msg_dict = {
            'name': 'Godiskungen',
            'admin': 'Testadmin'
        }
        self.recipient_data = [{u'SenderAccepted': True,
                               u'AccountStatus':
                               {u'ServiceSupplier':
                               {u'Id': u'162021005448',
                               u'ServiceAdress': u'x', u'Name': u'x'}, u'Type': u'Secure',
                               u'RecipientId': u'192705178354', u'Pending': False}}]

        self.recipient_sender_not = [{u'SenderAccepted': False,
                                     u'AccountStatus':
                                     {u'ServiceSupplier':
                                     {u'Id': u'162021005448',
                                     u'ServiceAdress': u'x', u'Name': u'x'}, u'Type': u'Secure',
                                     u'RecipientId': u'192705178354', u'Pending': False}}]

        self.recipient_not = [{u'SenderAccepted': False,
                              u'AccountStatus':
                              {u'ServiceSupplier':
                              {u'Id': u'162021005448',
                              u'ServiceAdress': u'x', u'Name': u'x'}, u'Type': u'Not',
                              u'RecipientId': u'192705178354', u'Pending': False}}]


    @patch('smscom.SMSClient.send')
    def test_send_message_sms(self, sms_mock):
        sms_mock.return_value = True
        status = send_message.delay('sms', self.msg_dict, '+466666', 'test.tmpl', 'sv_SE').get()

        # Test that the template was actually used in send_message function call to the sms service
        template = load_template(celery.conf.get('TEMPLATE_DIR'), 'test.tmpl', self.msg_dict, 'sv_SE')
        expected = [call(template, 'Test sender', '+466666', prio=2)]
        self.assertEqual(sms_mock.mock_calls, expected)
        self.assertTrue(status)

    def test_send_message_invalid_phone_number(self):
        try:
            send_message.delay('sms', self.msg_dict, '+466666a', 'test.tmpl', 'sv_SE').get()
        except ValueError, e:
            self.assertEqual(e.message, "'to' is not a valid phone number")

    @patch('eduid_msg.tasks.MessageRelay.recipient')
    def test_is_reachable_cache(self, recipient_mock):
        recipient_mock.is_reachable.return_value = self.recipient_data
        status = is_reachable.delay('192705178354').get()
        self.assertTrue(status)
        mdb = self.conn['test']
        result = mdb['recipient_cache'].find_one({'identifier': '192705178354'})
        self.assertEqual(result['data']['AccountStatus']['ServiceSupplier']['Id'], '162021005448')

    @patch('eduid_msg.tasks.Service')
    @patch('eduid_msg.tasks.MessageRelay.recipient')
    @patch('eduid_msg.tasks.MessageRelay.message')
    def test_send_message_mm(self, message_mock, recipient_mock, service_mock):
        recipient_mock.is_reachable.return_value = self.recipient_data
        message_mock.create_secure_message.return_value = True
        message_mock.create_signed_delivery.return_value = True
        send_message.delay('mm', self.msg_dict, '192705178354', 'test.tmpl', 'sv_SE', subject='Test').get()

        # Test that the template was actually used in send_message function call to the mm service
        template = load_template(celery.conf.get('TEMPLATE_DIR'), 'test.tmpl', self.msg_dict, 'sv_SE')
        expected = [call.create_secure_message('Test', template, 'text/plain', 'svSE'),
                    call.create_signed_delivery(['192705178354'], True)]
        self.assertEqual(message_mock.mock_calls, expected)

    @patch('eduid_msg.tasks.Service')
    @patch('eduid_msg.tasks.MessageRelay.recipient')
    @patch('eduid_msg.tasks.MessageRelay.message')
    def test_send_message_mm_sender_not_accepted(self, message_mock, recipient_mock, service_mock):
        recipient_mock.is_reachable.return_value = self.recipient_sender_not
        message_mock.create_secure_message.return_value = True
        message_mock.create_signed_delivery.return_value = True
        status = send_message.delay('mm', self.msg_dict, '192705178354', 'test.tmpl', 'sv_SE', subject='Test').get()
        self.assertEqual(status, "SENDER_NOT")

    @patch('eduid_msg.tasks.Service')
    @patch('eduid_msg.tasks.MessageRelay.recipient')
    @patch('eduid_msg.tasks.MessageRelay.message')
    def test_send_message_mm_recipient_not_existing(self, message_mock, recipient_mock, service_mock):
        recipient_mock.is_reachable.return_value = self.recipient_not
        message_mock.create_secure_message.return_value = True
        message_mock.create_signed_delivery.return_value = True
        status = send_message.delay('mm', self.msg_dict, '192705178354', 'test.tmpl', 'sv_SE', subject='Test').get()
        self.assertEqual(status, "Not")
