from celery import Celery

from eduid.common.config.workers import MobConfig


class MobWorkerSingleton:
    """
    Celery is largely based on magic happening on import.

    We need to accommodate this and allow creation of a Celery instance pointing at the right
    set of tasks at import-time, and allow for the configuration to be updated at a later
    time when it is available (or in tests).
    """

    celery = Celery(include=['eduid.workers.lookup_mobile.tasks'])
    mob_config = MobConfig(app_name='app_name_NOT_SET')

    @classmethod
    def update_config(cls, config: MobConfig):
        cls.mob_config = config
        cls.celery.config_from_object(config.celery.dict())
        return None
