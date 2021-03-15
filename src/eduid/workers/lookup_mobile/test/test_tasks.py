from eduid.workers.lookup_mobile.testing import LookupMobileMongoTestCase


class MockException(Exception):
    pass


class TestTasks(LookupMobileMongoTestCase):

    def test_ping(self):
        ret = self.lookup_mobile_relay.ping()
        self.assertEqual(ret, 'pong for testing')
