from __future__ import absolute_import

from celery.utils.log import get_task_logger

from eduid.workers.lookup_mobile.client.mobile_lookup_client import MobileLookupClient
from eduid.workers.lookup_mobile.common import celery
from eduid.workers.lookup_mobile.worker import worker_config

if celery is None:
    raise RuntimeError('Must call eduid.workers.lookup_mobile.init_app before importing tasks')

logger = get_task_logger(__name__)


@celery.task
def find_mobiles_by_NIN(national_identity_number, number_region=None):
    """
    Searches mobile numbers registered to the given nin
    :param national_identity_number:
    :return: a list of formatted mobile numbers. Empty list if no numbers was registered to the nin
    """
    lookup_client = MobileLookupClient(logger, worker_config)
    return lookup_client.find_mobiles_by_NIN(national_identity_number, number_region)


@celery.task
def find_NIN_by_mobile(mobile_number):
    """
    Searches nin with the registered mobile number
    :param mobile_number:
    :return: the nin with the registered mobile number
    """
    lookup_client = MobileLookupClient(logger, worker_config)
    return lookup_client.find_NIN_by_mobile(mobile_number)
