from eduid_scimapi.config import ScimApiConfig
from eduid_scimapi.context import Context
from eduid_scimapi.testing import ScimApiTestCase


class TestContext(ScimApiTestCase):
    def test_init(self):
        config = ScimApiConfig.init_config(test_config=self.test_config)
        ctx = Context(name='test_app', config=config)
        self.assertEqual(ctx.base_url, 'http://localhost:8000/')
