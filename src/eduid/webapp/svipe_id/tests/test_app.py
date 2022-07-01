# -*- coding: utf-8 -*-


from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.svipe_id.app import svipe_id_init_app
from eduid.webapp.svipe_id.settings.common import SvipeIdConfig

__author__ = 'lundberg'


class SvipeIdTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self):
        super(SvipeIdTests, self).setUp()

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return svipe_id_init_app('testing', config)

    def update_config(self, config):
        config.update(
            {
                'oidc_rp_handler_config': {
                    'base_url': 'http://test.example.local',
                    'hash_seed': 'testing',
                    'post_logout_redirect_url': 'http://test.example.local/logout',
                }
            }
        )
        return config

    def tearDown(self):
        super(SvipeIdTests, self).tearDown()
        with self.app.app_context():
            self.app.central_userdb._drop_whole_collection()

    def test_app_starts(self):
        assert self.app.conf.app_name == "testing"

    def test_create_authn_url(self):
        pass
