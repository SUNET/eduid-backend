from celery import Celery

from eduid.common.config.workers import AmConfig
from eduid.workers.am.fetcher_registry import AFRegistry


class AmWorkerSingleton:
    """
    Celery is largely based on magic happening on import.

    We need to accommodate this and allow creation of a Celery instance pointing at the right
    set of tasks at import-time, and allow for the configuration to be updated at a later
    time when it is available (or in tests).
    """

    celery = Celery(include=['eduid.workers.am.tasks'])
    am_config = AmConfig(app_name='app_name_NOT_SET')
    af_registry = AFRegistry()

    @classmethod
    def update_config(cls, config: AmConfig):
        cls.am_config = config
        cls.celery.config_from_object(config.celery.dict())
        return None
