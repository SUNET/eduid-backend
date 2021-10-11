import json
from datetime import datetime

from bson import ObjectId
from saml2.saml import NameID


class EduidJSONEncoder(json.JSONEncoder):
    # TODO: This enables us to serialise NameIDs into the stored sessions,
    #       but we don't seem to de-serialise them on load
    def default(self, obj):
        if isinstance(obj, NameID):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, ObjectId):
            return str(obj)

        return super().default(obj)
