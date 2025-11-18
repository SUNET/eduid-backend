from celery import Celery

from eduid.common.config.base import CeleryConfig
from eduid.common.config.workers import AmConfig
from eduid.workers.am.fetcher_registry import AFRegistry


class AmCelerySingleton:
    """
    Celery is largely based on magic happening on import.

    We need to accommodate this and allow creation of a Celery instance pointing at the right
    set of tasks at import-time, and allow for the configuration to be updated at a later
    time when it is available (or in tests).

    This instance is used both in 'worker' mode (in the backend),
    and in 'client' mode in the webapp etc. that invokes the task.
    """

    celery = Celery(include=["eduid.workers.am.tasks"])
    worker_config = AmConfig(app_name="app_name_NOT_SET")
    af_registry = AFRegistry()

    @classmethod
    def update_worker_config(cls, config: AmConfig) -> None:
        cls.worker_config = config
        cls.update_celery_config(config.celery)

    @classmethod
    def update_celery_config(cls, config: CeleryConfig) -> None:
        cls.celery.config_from_object(config.model_dump())
