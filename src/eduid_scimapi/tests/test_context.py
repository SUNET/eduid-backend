import unittest
from eduid_scimapi.context import Context

class TestContext(unittest.TestCase):

    def test_init(self):
        ctx = Context(config={'mongo_uri': 'mongodb://mongodb'}, testing=True)
        self.assertEqual(ctx.base_url, 'http://localhost:8000')
