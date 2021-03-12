from typing import List, Optional

from celery import Task
from celery.utils.log import get_task_logger

from eduid.workers.lookup_mobile.client.mobile_lookup_client import MobileLookupClient
from eduid.workers.lookup_mobile.common import MobCelerySingleton

logger = get_task_logger(__name__)

app = MobCelerySingleton.celery

class MobWorker(Task):
    """ Singleton that stores reusable objects like the MobileLookupClient """

    abstract = True  # This means Celery won't register this as another task

    def __init__(self):
        self._lookup_client: Optional[MobileLookupClient] = None

    @property
    def lookup_client(self) -> Optional[MobileLookupClient]:
        if not self._lookup_client:
            self._lookup_client = MobileLookupClient(logger, MobCelerySingleton.worker_config)
        return self._lookup_client


@app.task(bind=True, base=MobWorker)
def find_mobiles_by_NIN(self: MobWorker, national_identity_number: str, number_region=None) -> List[str]:
    """
    Searches mobile numbers registered to the given nin
    :param national_identity_number:
    :return: a list of formatted mobile numbers. Empty list if no numbers was registered to the nin
    """
    return self.lookup_client.find_mobiles_by_NIN(national_identity_number, number_region)


@app.task(bind=True, base=MobWorker)
def find_NIN_by_mobile(self: MobWorker, mobile_number: str) -> Optional[str]:
    """
    Searches nin with the registered mobile number
    :param mobile_number:
    :return: the nin with the registered mobile number
    """
    return self.lookup_client.find_NIN_by_mobile(mobile_number)
