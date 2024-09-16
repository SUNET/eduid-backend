import json
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from bson import ObjectId
from pydantic import TypeAdapter
from saml2.saml import NameID


class EduidJSONEncoder(json.JSONEncoder):
    # TODO: This enables us to serialise NameIDs into the stored sessions,
    #       but we don't seem to de-serialise them on load
    def default(self, o: Any) -> str | Any:
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, timedelta):
            return TypeAdapter(timedelta).dump_python(o, mode="json")
        if isinstance(o, ObjectId | NameID):
            return str(o)
        if isinstance(o, Enum):
            return o.value

        return super().default(o)
