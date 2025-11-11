__author__ = "lundberg"

#
#  This is a copy of decorators.py in the eduid.workers.msg project. Both should be move in to a
#  logging module at a later stage.
#

from collections.abc import Callable
from inspect import isclass
from typing import Any

from pymongo.collection import Collection

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.db import MongoDB
from eduid.userdb.db.base import TUserDbDocument


class TransactionAudit:
    enabled = True
    db_uri = None

    def __init__(self, db_name: str = "eduid_lookup_mobile", collection_name: str = "transaction_audit") -> None:
        self.db_name: str = db_name
        self.collection_name: str = collection_name
        self.collection: Collection[TUserDbDocument] | None = None

    def __call__(self, f: Callable[..., Any]) -> Callable[..., Any]:
        if not self.enabled:
            return f

        def audit(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
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
                    date = utc_now()
                    doc = TUserDbDocument(
                        {
                            "function": f.__name__,
                            "data": self._filter(f.__name__, ret, *args, **kwargs),
                            "created_at": date,
                        }
                    )
                    self.collection.insert_one(doc)
            return ret

        return audit

    @classmethod
    def enable(cls) -> None:
        cls.enabled = True

    @classmethod
    def disable(cls) -> None:
        cls.enabled = False

    def _filter(self, func: str, data: Any, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        if data is False:
            return data
        if func == "find_mobiles_by_NIN":
            number_region = None
            ARGS_INCLUDE_REGION = 3
            if len(args) == ARGS_INCLUDE_REGION:
                number_region = args[2]
            return {"national_identity_number": args[1], "number_region": number_region, "data_returned": bool(data)}
        elif func == "find_NIN_by_mobile":
            return {"mobile_number": args[1], "data_returned": bool(data)}
        return data
