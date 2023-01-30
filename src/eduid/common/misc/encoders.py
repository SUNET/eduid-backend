import json
from datetime import datetime
from typing import Any, Union

from bson import ObjectId
from saml2.saml import NameID


class EduidJSONEncoder(json.JSONEncoder):
    # TODO: This enables us to serialise NameIDs into the stored sessions,
    #       but we don't seem to de-serialise them on load
    def default(self, o: Any) -> Union[str, Any]:
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, (ObjectId, NameID)):
            return str(o)

        return super().default(o)
