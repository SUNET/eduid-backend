from eduid.workers.lookup_mobile.testing import LookupMobileMongoTestCase


class MockException(Exception):
    pass


class TestTasks(LookupMobileMongoTestCase):
    def test_ping(self) -> None:
        ret = self.lookup_mobile_relay.ping()
        assert ret == "pong for testing"

    def test_mobile_to_nin(self) -> None:
        ret = self.lookup_mobile_relay.find_nin_by_mobile("+46701740610")
        assert ret == "200202027140"
