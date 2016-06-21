# -*- coding: utf-8 -*-

from __future__ import absolute_import

from os import devnull
import json
from datetime import datetime
from collections import OrderedDict
from mock import patch
from bson import ObjectId

from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.letter_proofing.app import init_letter_proofing_app

__author__ = 'lundberg'


class AppTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self):
        super(AppTests, self).setUp()

        self.test_user_eppn = 'hubba-bubba'
        self.test_user_nin = '200001023456'
        self.mock_address = OrderedDict([
            (u'Name', OrderedDict([
                (u'GivenNameMarking', u'20'), (u'GivenName', u'Testaren Test'),
                (u'Surname', u'Testsson')])),
            (u'OfficialAddress', OrderedDict([(u'Address2', u'\xd6RGATAN 79 LGH 10'),
                                              (u'PostalCode', u'12345'),
                                              (u'City', u'LANDET')]))
        ])
        self._json = 'application/json'
        self.client = self.app.test_client()
        self.session_cookie = self.get_session_cookie(self.test_user_eppn)

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_letter_proofing_app('testing', config)

    def update_config(self, config):
        config.update({
            'EKOPOST_DEBUG_PDF': devnull,
            'LETTER_WAIT_TIME_HOURS': 336,
            'CELERY_CONFIG': {
                'BROKER_URL': 'amqp://dummy',
                'CELERY_RESULT_BACKEND': 'amqp',
                'CELERY_TASK_SERIALIZER': 'json'
            },
        })
        return config

    def tearDown(self):
        super(AppTests, self).tearDown()
        with self.app.app_context():
            self.app.proofing_statedb._drop_whole_collection()
            self.app.central_userdb._drop_whole_collection()

    # Helper methods
    def get_state(self):
        response = self.client.get('/get-state', headers={'Cookie': self.session_cookie})
        self.assertEqual(response.status_code, 200)
        return json.loads(response.data)

    @patch('eduid_webapp.letter_proofing.views.get_postal_address')
    def send_letter(self, nin, mock_get_postal_address):
        mock_get_postal_address.return_value = self.mock_address
        data = {'nin': nin}
        response = self.client.post('/send-letter', data=json.dumps(data), content_type=self._json,
                                    headers={'Cookie': self.session_cookie})
        self.assertEqual(response.status_code, 200)
        return json.loads(response.data)

    def verify_code(self, code):
        data = {'verification_code': code}
        response = self.client.post('/verify-code', data=json.dumps(data), content_type=self._json,
                                    headers={'Cookie': self.session_cookie})
        self.assertEqual(response.status_code, 200)
        return json.loads(response.data)
    # End helper methods

    def test_authenticate(self):
        response = self.client.get('/get-state')
        self.assertEqual(response.status_code, 302)  # Redirect to token service
        response = self.client.get('/get-state', headers={'Cookie': self.session_cookie})
        self.assertEqual(response.status_code, 200)  # Authenticated request

    def test_letter_not_sent_status(self):
        json_data = self.get_state()
        self.assertNotIn('letter_sent', json_data)

    def test_send_letter(self):
        json_data = self.send_letter(self.test_user_nin)
        expires = json_data['letter_expires']
        expires = datetime.utcfromtimestamp(int(expires))
        self.assertIsInstance(expires, datetime)
        expires = expires.strftime('%Y-%m-%d')
        self.assertIsInstance(expires, str)

    def test_letter_sent_status(self):
        self.send_letter(self.test_user_nin)
        json_data = self.get_state()
        self.assertIn('letter_sent', json_data)
        expires = datetime.utcfromtimestamp(int(json_data['letter_expires']))
        self.assertIsInstance(expires, datetime)
        expires = expires.strftime('%Y-%m-%d')
        self.assertIsInstance(expires, str)

    def test_verify_letter_code(self):
        self.send_letter(self.test_user_nin)
        with self.app.test_request_context():
            with self.app.app_context():
                proofing_state = self.app.proofing_statedb.get_state_by_eppn(self.test_user_eppn,
                                                                             raise_on_missing=False)
        json_data = self.verify_code(proofing_state.nin.verification_code)
        self.assertTrue(json_data['success'])

    def test_verify_letter_code_fail(self):
        self.send_letter(self.test_user_nin)
        json_data = self.verify_code('wrong code')
        self.assertFalse(json_data['success'])

    def test_proofing_flow(self):
        self.get_state()
        self.send_letter(self.test_user_nin)
        self.get_state()
        with self.app.test_request_context():
            user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn, raise_on_missing=True)
            proofing_state = self.app.proofing_statedb.get_state_by_eppn(user.eppn, raise_on_missing=False)
        json_data = self.verify_code(proofing_state.nin.verification_code)
        self.assertTrue(json_data['success'])

    def test_expire_proofing_state(self):
        self.send_letter(self.test_user_nin)
        json_data = self.get_state()
        self.assertIn('letter_sent', json_data)
        self.app.config.update({'LETTER_WAIT_TIME_HOURS': -1})
        json_data = self.get_state()
        self.assertTrue(json_data['letter_expired'])
        self.assertNotIn('letter_sent', json_data)

    def test_deprecated_proofing_state(self):
        deprecated_data = {
            'user_id': ObjectId('012345678901234567890123'),
            'nin': {
                'created_by': 'eduid-userdb.tests',
                'created_ts': datetime(2015, 11, 9, 12, 53, 9, 708761),
                'number': '200102034567',
                'verification_code': 'abc123',
                'verified': False
            },
            'proofing_letter': {
                'is_sent': False,
                'sent_ts': None,
                'transaction_id': None,
                'address': self.mock_address
            }
        }
        with self.app.app_context():
            self.app.proofing_statedb._coll.insert(deprecated_data)
            state = self.app.proofing_statedb.get_state_by_user_id('012345678901234567890123', self.test_user_eppn)
        self.assertIsNotNone(state)
        state_dict = state.to_dict()
        self.assertItemsEqual(state_dict.keys(), ['_id', 'eduPersonPrincipalName', 'nin', 'proofing_letter',
                                                  'modified_ts'])
        self.assertItemsEqual(state_dict['nin'].keys(), ['created_by', 'created_ts', 'number', 'verification_code',
                                                         'verified'])
        self.assertItemsEqual(state_dict['proofing_letter'].keys(), ['is_sent', 'sent_ts', 'transaction_id',
                                                                     'address'])
