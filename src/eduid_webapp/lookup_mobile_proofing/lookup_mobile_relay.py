import eduid_lookup_mobile.celery
from eduid_lookup_mobile.tasks import find_mobiles_by_NIN, find_NIN_by_mobile

__author__ = 'mathiashedstrom'


def init_relay(app):
    config = app.config['CELERY_CONFIG']
    config['BROKER_URL'] = app.config['LOOKUP_MOBILE_BROKER_URL']
    eduid_lookup_mobile.celery.app.conf.update(config)
    app.lookup_mobile_relay = LookupMobileRelay()
    return app


class LookupMobileTaskFailed(Exception):
    pass


class LookupMobileRelay(object):

    def __init__(self):
        self._find_mobiles_by_NIN = find_mobiles_by_NIN
        self._find_NIN_by_mobile = find_NIN_by_mobile

    def find_nin_by_mobile(self, mobile_number):
        try:
            result = self._find_NIN_by_mobile.delay(mobile_number)
            result = result.get(timeout=10)  # Lower timeout than standard gunicorn worker timeout (25)
            return result
        except Exception as e:
            raise LookupMobileTaskFailed('find_nin_by_mobile task failed: {}'.format(e))

    def find_mobiles_by_nin(self, nin):
        try:
            result = self._find_mobiles_by_NIN.delay(nin)
            result = result.get(timeout=10)  # Lower timeout than standard gunicorn worker timeout (25)
            return result
        except Exception as e:
            raise LookupMobileTaskFailed('find_mobiles_by_nin task failed: {}'.format(e))
