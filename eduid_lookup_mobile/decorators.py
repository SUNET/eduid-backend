# -*- coding: utf-8 -*-
__author__ = 'lundberg'

from eduid_userdb.db import MongoDB
from inspect import isclass
from datetime import datetime


class TransactionAudit(object):
    enabled = False
    collection = None

    def __init__(self, db_uri, db_name='eduid_msg', collection_name='transaction_audit'):
        self.db_uri = db_uri
        self.db_name = db_name
        self.collection_name = collection_name

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
        if self.collection is None:
            conn = MongoDB(self.db_uri)
            db = conn.get_database(self.db_name)
            self.collection = db[self.collection_name]
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

