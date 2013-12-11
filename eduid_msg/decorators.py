from eduid_msg.db import MongoDB
from inspect import isclass, getmembers


class TransactionAudit(object):
    def __init__(self, db_uri, db_name='eduid_msg', collection='transaction_audit'):
        self.conn = MongoDB(db_uri)
        self.db = self.conn.get_database(db_name)
        self.collection = self.db[collection]

    def __call__(self, f):
        def audit(*args, **kwargs):
            ret = f(*args, **kwargs)
            if not isclass(ret):  # we can't save class objects in mongodb
                doc = {'function': f.__name__,
                       'data': ret}
                self.collection.insert(doc)
            return ret
        return audit
