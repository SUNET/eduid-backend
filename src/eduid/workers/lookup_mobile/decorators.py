__author__ = "lundberg"

#
#  This is a copy of decorators.py in the eduid.workers.msg project. Both should be move in to a
#  logging module at a later stage.
#

from datetime import datetime
from inspect import isclass

from eduid.userdb.db import MongoDB


class TransactionAudit:
    enabled = True
    db_uri = None

    def __init__(self, db_name="eduid_lookup_mobile", collection_name="transaction_audit"):
        self.db_name = db_name
        self.collection_name = collection_name
        self.collection = None

    def __call__(self, f):

        if not self.enabled:
            return f

        def audit(*args, **kwargs):
            ret = f(*args, **kwargs)
            # XXX Ugly hack
            # The class that uses the decorator needs to have self.conf['MONGO_URI'] and self.transaction_audit set
            # args[0] is wrapped methods self.
            self.enabled = getattr(args[0], "transaction_audit", False)
            if self.enabled:
                if self.collection is None:
                    self.db_uri = args[0].conf.mongo_uri
                    # Do not initialize the db connection before we know the decorator is actually enabled
                    db = MongoDB(db_uri=self.db_uri, db_name=self.db_name)
                    self.collection = db.get_collection(self.collection_name)
                if not isclass(ret):  # we can't save class objects in mongodb
                    date = datetime.utcnow()
                    doc = {
                        "function": f.__name__,
                        "data": self._filter(f.__name__, ret, *args, **kwargs),
                        "created_at": date,
                    }
                    self.collection.insert_one(doc)
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
        if func == "find_mobiles_by_NIN":
            number_region = None
            if len(args) == 3:
                number_region = args[2]
            return {"national_identity_number": args[1], "number_region": number_region, "data_returned": bool(data)}
        elif func == "find_NIN_by_mobile":
            return {"mobile_number": args[1], "data_returned": bool(data)}
        return data
