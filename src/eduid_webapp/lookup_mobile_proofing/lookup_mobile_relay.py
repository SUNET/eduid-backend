import eduid_lookup_mobile

__author__ = 'mathiashedstrom'


def init_relay(app):
    app.lookup_mobile_relay = LookupMobileRelay(app.config.celery_config)
    return app


class LookupMobileTaskFailed(Exception):
    pass


class LookupMobileRelay(object):
    def __init__(self, config):
        eduid_lookup_mobile.init_app(config)
        # these have to be imported _after_ eduid_lookup_mobile.init_app()
        from eduid_lookup_mobile.tasks import find_mobiles_by_NIN, find_NIN_by_mobile

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
