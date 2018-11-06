# -*- coding: utf-8 -*-

from __future__ import absolute_import

from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.support.app import support_init_app

__author__ = 'lundberg'


class SupportAppTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self):
        super(SupportAppTests, self).setUp()

        self.test_user_eppn = 'hubba-bubba'
        self.client = self.app.test_client()

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        res = support_init_app('testing', config)
        with self.app.app_context():
            # have EduidAPITestCase.tearDown() clean up these databases
            self.cleanup_databases = [self.app.support_user_db,
                                      self.app.support_authn_db,
                                      self.app.support_proofing_log_db,
                                      self.app.support_signup_db,
                                      self.app.support_actions_db,
                                      self.app.support_letter_proofing_db,
                                      self.app.central_userdb,
                                      ]
        return res

    def update_config(self, config):
        config.update({
            'SUPPORT_PERSONNEL': ['hubba-bubba'],
        })
        return config

    def test_authenticate(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)  # Redirect to token service
        with self.session_cookie(self.client, self.test_user_eppn) as client:
            response = client.get('/')
        self.assertEqual(response.status_code, 200)  # Authenticated request

