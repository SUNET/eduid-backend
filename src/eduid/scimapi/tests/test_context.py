from eduid_common.config.parsers import load_config

from eduid_scimapi.config import ScimApiConfig
from eduid_scimapi.context import Context
from eduid_scimapi.testing import ScimApiTestCase


class TestContext(ScimApiTestCase):
    def test_init(self):
        config = load_config(typ=ScimApiConfig, app_name='scimapi', ns='api', test_config=self.test_config)
        ctx = Context(config=config)
        self.assertEqual(ctx.base_url, 'http://localhost:8000/')
