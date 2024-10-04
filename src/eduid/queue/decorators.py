from collections.abc import Callable
from inspect import isclass
from typing import Any

from pymongo.synchronous.collection import Collection

from eduid.userdb.db import MongoDB

# TODO: Refactor but keep transaction audit document structure
from eduid.userdb.db.base import TUserDbDocument
from eduid.userdb.util import utc_now


class TransactionAudit:
    enabled = False

    def __init__(self, db_uri: str, db_name: str = "eduid_queue", collection_name: str = "transaction_audit") -> None:
        self._conn: MongoDB | None = None
        self.db_uri: str = db_uri
        self.db_name: str = db_name
        self.collection_name: str = collection_name
        self.collection: Collection[TUserDbDocument] | None = None

    def __call__(self, f: Callable[..., Any]) -> Callable[..., Any]:
        if not self.enabled:
            return f

        def audit(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
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
    def enable(cls) -> None:
        cls.enabled = True

    @classmethod
    def disable(cls) -> None:
        cls.enabled = False

    @staticmethod
    def _filter(func: str, data: object, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
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
