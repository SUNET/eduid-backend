import logging

from eduid.common.config.base import CeleryConfigMixin, EduIDBaseAppConfig
from eduid.common.config.workers import MobConfig
from eduid.common.rpc.lookup_mobile_relay import LookupMobileRelay
from eduid.userdb.testing import MongoTestCase, SetupConfig
from eduid.workers.lookup_mobile.common import MobCelerySingleton

logger = logging.getLogger(__name__)


class MobTestConfig(EduIDBaseAppConfig, CeleryConfigMixin):
    pass


class LookupMobileMongoTestCase(MongoTestCase):
    def setUp(self, config: SetupConfig | None = None) -> None:
        super().setUp(config=config)
        if config is None:
            config = SetupConfig()
        if config.init_lookup_mobile:
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
                "testing": True,
            }
            self.lookup_mobile_settings = MobConfig(**settings)

            MobCelerySingleton.update_worker_config(self.lookup_mobile_settings)
            logger.debug(f"Initialised lookup_mobile with config:\n{self.lookup_mobile_settings}")

            self.lookup_mobile_relay = LookupMobileRelay(MobTestConfig(**settings))
