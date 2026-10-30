from eduid.workers.msg.testing import MsgMongoTestCase


class TestTasks(MsgMongoTestCase):
    def test_ping(self) -> None:
        ret = self.msg_relay.ping()
        assert ret == "pong for testing"
