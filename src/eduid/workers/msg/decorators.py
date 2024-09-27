from collections.abc import Callable
from datetime import datetime
from inspect import isclass
from typing import Any

from eduid.userdb.db import MongoDB


class TransactionAudit:
    enabled = False
    db_uri: str | None = None
    db_name: str = "eduid_msg"
    collection_name: str = "transaction_audit"

    def __init__(self):
        self._conn = None
        self.collection = None

    def __call__(self, f: Callable[..., Any]) -> Callable[..., Any]:
        if not self.enabled:
            return f

        def audit(*args, **kwargs):
            ret = f(*args, **kwargs)
            if not isclass(ret):  # we can't save class objects in mongodb
                date = datetime.utcnow()
                doc = {
                    "function": f.__name__,
                    "data": self._filter(f.__name__, ret, *args, **kwargs),
                    "created_at": date,
                }
                if self.collection is not None:
                    self.collection.insert_one(doc)
            return ret

        if self._conn is None or not self._conn.is_healthy():
            if self.db_uri:
                self._conn = MongoDB(self.db_uri)
                self.collection = self._conn.get_collection(self.collection_name, database_name=self.db_name)
        return audit

    @classmethod
    def enable(cls, db_uri: str, db_name: str | None = None):
        if isinstance(db_uri, str):
            cls.db_uri = db_uri
        if db_name is not None:
            cls.db_name = db_name
        cls.enabled = True

    @classmethod
    def disable(cls):
        cls.enabled = False

    @staticmethod
    def _filter(func: str, data: Any, *args, **kwargs):
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
            return {"type": "mail", "recipient": args[2], "send_errors": data, "audit_reference": args[4]}
        elif func == "sendsms":
            return {"type": "sms", "recipient": args[1], "transaction_id": data, "audit_reference": args[3]}
        return data
