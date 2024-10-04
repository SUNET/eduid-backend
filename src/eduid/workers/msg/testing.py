import logging
from pathlib import PurePath

from eduid.common.config.base import EduIDBaseAppConfig, MailConfigMixin, MsgConfigMixin
from eduid.common.config.workers import MsgConfig
from eduid.common.rpc.mail_relay import MailRelay
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.userdb.testing import MongoTestCase, SetupConfig
from eduid.workers.msg.common import MsgCelerySingleton

logger = logging.getLogger(__name__)


class MsgTestConfig(MsgConfig, MsgConfigMixin):
    pass


class MailTestConfig(EduIDBaseAppConfig, MailConfigMixin):
    pass


class MsgMongoTestCase(MongoTestCase):
    def setUp(self, config: SetupConfig | None = None) -> None:
        super().setUp(config=config)
        data_path = PurePath(__file__).with_name("tests") / "data"
        if config is None:
            config = SetupConfig()
        if config.init_msg:
            settings = {
                "app_name": "testing",
                "celery": {
                    "broker_transport": "memory",
                    "broker_url": "memory://",
                    "task_eager_propagates": True,
                    "task_always_eager": True,
                    "result_backend": "cache",
                    "cache_backend": "memory",
                },
                "mongo_uri": self.tmp_db.uri,
                "mongo_dbname": "test",
                "sms_acc": "foo",
                "sms_key": "bar",
                "sms_sender": "Test sender",
                "template_dir": str(data_path),
                "message_rate_limit": 2,
            }
            self.msg_settings = MsgTestConfig(**settings)

            MsgCelerySingleton.update_worker_config(self.msg_settings)
            logger.debug(f"Initialised message_relay with config:\n{self.msg_settings}")

            self.msg_relay = MsgRelay(self.msg_settings)
            self.mail_relay = MailRelay(MailTestConfig(**settings))
