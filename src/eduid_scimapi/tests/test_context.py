from neo4j import basic_auth

from eduid_scimapi.testing import ScimApiTestCase
from eduid_scimapi.config import ScimApiConfig

from eduid_scimapi.context import Context


class TestContext(ScimApiTestCase):

    def setUp(self) -> None:
        self.config = {
            'mongo_uri': self.mongo_uri,
            'neo4j_uri': self.neo4j_uri,
            'neo4j_config': {'encrypted': False}
        }
    def test_init(self):
        config = ScimApiConfig.init_config(test_config=self.config)
        ctx = Context(config=config)
        self.assertEqual(ctx.base_url, 'http://localhost:8000/')
