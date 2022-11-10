from inspect import isclass

from eduid.userdb.db import MongoDB

# TODO: Refactor but keep transaction audit document structure
from eduid.userdb.util import utc_now


class TransactionAudit(object):
    enabled = False

    def __init__(self, db_uri, db_name="eduid_queue", collection_name="transaction_audit"):
        self._conn = None
        self.db_uri = db_uri
        self.db_name = db_name
        self.collection_name = collection_name
        self.collection = None

    def __call__(self, f):
        if not self.enabled:
            return f

        def audit(*args, **kwargs):
            ret = f(*args, **kwargs)
            if not isclass(ret) and self.collection:  # we can't save class objects in mongodb
                date = utc_now()
                doc = {
                    "function": f.__name__,
                    "data": self._filter(f.__name__, ret, *args, **kwargs),
                    "created_at": date,
                }
                self.collection.insert_one(doc)
            return ret

        if self._conn is None or not self._conn.is_healthy():
            self._conn = MongoDB(self.db_uri)
            db = self._conn.get_database(self.db_name)
            self.collection = db[self.collection_name]
        return audit

    @classmethod
    def enable(cls):
        cls.enabled = True

    @classmethod
    def disable(cls):
        cls.enabled = False

    @staticmethod
    def _filter(func, data, *args, **kwargs):
        if data is False:
            return data
        if func == "_get_navet_data":
            return {"identity_number": args[1]}
        elif func == "send_message":
            return {
                "type": args[1],
                "recipient": args[4],
                "transaction_id": data,
                "audit_reference": args[2],
                "template": args[5],
            }
        elif func == "sendmail":
            return {"type": "mail", "recipient": args[1], "send_errors": data, "audit_reference": args[3]}
        elif func == "sendsms":
            return {"type": "sms", "recipient": args[1], "transaction_id": data, "audit_reference": args[3]}
        return data
