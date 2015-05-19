# -*- coding: utf-8 -*-
__author__ = 'lundberg'

#
#  This is a copy of decorators.py in the eduid_msg project. Both should be move in to a
#  logging module at a later stage.
#

from eduid_userdb.db import MongoDB
from inspect import isclass
from datetime import datetime


class TransactionAudit(object):
    enabled = False

    def __init__(self, db_uri, collection_name='transaction_audit'):
        self.collection = MongoDB(db_uri).get_collection(collection_name)

    def __call__(self, f):
        if not self.enabled:
            return f

        def audit(*args, **kwargs):
            ret = f(*args, **kwargs)
            if not isclass(ret):  # we can't save class objects in mongodb
                date = datetime.utcnow()
                doc = {'function': f.__name__,
                       'data': self._filter(f.__name__, ret, *args, **kwargs),
                       'created_at': date}
                self.collection.insert(doc)
            return ret
        return audit

    @classmethod
    def enable(cls):
        cls.enabled = True

    @classmethod
    def disable(cls):
        cls.enabled = False

    def _filter(self, func, data, *args, **kwargs):
        if data is False:
            return data
        if func == 'find_mobiles_by_NIN':
            number_region = None
            if len(args) == 3:
                number_region = args[2]
            return {'national_identity_number': args[1], 'number_region': number_region, 'success': bool(data)}
        elif func == 'find_NIN_by_mobile':
            return {'mobile_number': args[1], 'success': bool(data)}
        return data

