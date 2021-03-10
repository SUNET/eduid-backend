from typing import List, Optional

from celery.utils.log import get_task_logger

from eduid.workers.lookup_mobile.client.mobile_lookup_client import MobileLookupClient
from eduid.workers.lookup_mobile.common import MobWorkerSingleton

logger = get_task_logger(__name__)

app = MobWorkerSingleton.celery


@app.task
def find_mobiles_by_NIN(national_identity_number: str, number_region=None) -> List[str]:
    """
    Searches mobile numbers registered to the given nin
    :param national_identity_number:
    :return: a list of formatted mobile numbers. Empty list if no numbers was registered to the nin
    """
    lookup_client = MobileLookupClient(logger, MobWorkerSingleton.mob_config)
    return lookup_client.find_mobiles_by_NIN(national_identity_number, number_region)


@app.task
def find_NIN_by_mobile(mobile_number: str) -> Optional[str]:
    """
    Searches nin with the registered mobile number
    :param mobile_number:
    :return: the nin with the registered mobile number
    """
    lookup_client = MobileLookupClient(logger, MobWorkerSingleton.mob_config)
    return lookup_client.find_NIN_by_mobile(mobile_number)
