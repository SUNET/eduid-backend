from typing import Any

import eduid.workers.lookup_mobile

__author__ = "mathiashedstrom"
from eduid.common.config.base import CeleryConfigMixin
from eduid.common.decorators import deprecated
from eduid.common.rpc.exceptions import LookupMobileTaskFailed


class LookupMobileRelay:
    def __init__(self, config: CeleryConfigMixin) -> None:
        self.app_name = config.app_name
        eduid.workers.lookup_mobile.init_app(config.celery)
        # these have to be imported _after_ eduid.workers.lookup_mobile.init_app()
        from eduid.workers.lookup_mobile.tasks import find_mobiles_by_NIN, find_NIN_by_mobile, pong

        self._find_mobiles_by_NIN = find_mobiles_by_NIN
        self._find_NIN_by_mobile = find_NIN_by_mobile
        self._pong = pong

    def find_nin_by_mobile(self, mobile_number: str) -> str | None:
        try:
            result = self._find_NIN_by_mobile.delay(mobile_number)
            result = result.get(timeout=10)  # Lower timeout than standard gunicorn worker timeout (25)
            return result
        except Exception as e:
            raise LookupMobileTaskFailed(f"find_nin_by_mobile task failed: {e}")

    @deprecated("This task seems unused")
    def find_mobiles_by_nin(self, nin: str) -> Any:
        try:
            result = self._find_mobiles_by_NIN.delay(nin)
            result = result.get(timeout=10)  # Lower timeout than standard gunicorn worker timeout (25)
            return result
        except Exception as e:
            raise LookupMobileTaskFailed(f"find_mobiles_by_nin task failed: {e}")

    def ping(self, timeout: int = 1) -> str:
        """
        Check if this application is able to reach an LookupMobile worker.
        :return: Result of celery Task.get
        """
        rtask = self._pong.apply_async(kwargs={"app_name": self.app_name})
        try:
            return rtask.get(timeout=timeout)
        except Exception as e:
            rtask.forget()
            raise LookupMobileTaskFailed(f"ping task failed: {repr(e)}")
