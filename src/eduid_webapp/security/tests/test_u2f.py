# -*- coding: utf-8 -*-
from __future__ import absolute_import

import json
import time

from flask import current_app
from mock import patch

from eduid_common.api.testing import EduidAPITestCase
from eduid_common.api.utils import retrieve_modified_ts
from eduid_webapp.security.app import security_init_app

__author__ = 'lundberg'


class SecurityTests(EduidAPITestCase):

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return security_init_app('testing', config)

    def update_config(self, config):
        config.update({
            'AVAILABLE_LANGUAGES': {'en': 'English','sv': 'Svenska'},
            'MSG_BROKER_URL': 'amqp://dummy',
            'AM_BROKER_URL': 'amqp://dummy',
            'CELERY_CONFIG': {
                'CELERY_RESULT_BACKEND': 'amqp',
                'CELERY_TASK_SERIALIZER': 'json'
            },
            'UF2_APP_ID': 'https://eduid.se/u2f-app-id.json',
            'U2F_MAX_ALLOWED_TOKENS': 2
        })
        return config

    def init_data(self):
        self.app.dashboard_userdb.save(self.test_user, check_sync=False)
        retrieve_modified_ts(self.test_user)

    def test_enroll_first_key(self):
        response = self.browser.get('/u2f/enroll')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/u2f/enroll')

            enroll_data = json.loads(response2.data)
            self.assertEqual(enroll_data['type'], 'GET_U2F_U2F_ENROLL_SUCCESS')
            self.assertEqual(enroll_data['payload']['appId'], 'https://eduid.se/u2f-app-id.json')
            self.assertEqual(enroll_data['payload']['registeredKeys'], [])
            self.assertIn('challenge', enroll_data['payload']['registerRequests'][0])
            self.assertIn('version', enroll_data['payload']['registerRequests'][0])
