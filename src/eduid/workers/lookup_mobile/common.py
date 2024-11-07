from celery import Celery

from eduid.common.config.base import CeleryConfig
from eduid.common.config.workers import MobConfig


class MobCelerySingleton:
    """
    Celery is largely based on magic happening on import.

    We need to accommodate this and allow creation of a Celery instance pointing at the right
    set of tasks at import-time, and allow for the configuration to be updated at a later
    time when it is available (or in tests).

    This instance is used both in 'worker' mode (in the backend),
    and in 'client' mode in the webapp etc. that invokes the task.
    """

    celery = Celery(include=["eduid.workers.lookup_mobile.tasks"])
    worker_config = MobConfig(app_name="app_name_NOT_SET")

    @classmethod
    def update_worker_config(cls, config: MobConfig) -> None:
        cls.worker_config = config
        cls.update_celery_config(config.celery)
        return None

    @classmethod
    def update_celery_config(cls, config: CeleryConfig) -> None:
        cls.celery.config_from_object(config.dict())
        return None
