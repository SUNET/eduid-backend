from typing import Any, Dict, Optional, Set

from eduid.userdb.db import BaseDB
from eduid.userdb.util import utc_now


class CacheMDB(BaseDB):

    _init_collections: Set[str] = set()

    def __init__(self, db_uri: str, db_name: str, collection: str, ttl: int):
        super().__init__(db_uri=db_uri, db_name=db_name, collection=collection)
        indexes = {
            # Remove cache entries after TTL expires
            'auto-discard': {'key': [('created_at', 1)], 'expireAfterSeconds': ttl},
            # Ensure unique cache item identifier
            'unique-scimid': {'key': [('identifier', 1)], 'unique': True},
        }
        self.setup_indexes(indexes)

    def add_cache_item(self, identifier: str, data: Dict[str, Any]):
        date = utc_now()
        doc = {'identifier': identifier, 'data': data, 'created_at': date}
        self._coll.insert_one(doc)
        return True

    def get_cache_item(self, identifier: str) -> Optional[Dict[str, Any]]:
        query = {'identifier': identifier}
        result = self._coll.find_one(query)
        if result is not None:
            return result['data']
        return result

    def get_cached_items_by_query(self, query):
        result = self._coll.find(query)
        return result

    def update_cache_item(self, identifier: str, data: Dict[str, Any]):
        date = utc_now()
        return self._coll.update(
            {'identifier': identifier}, {'$set': {'data': data, 'updated_at': date}}, w=1, getLastError=True
        )

    def remove_cache_item(self, identifier: str):
        return self._coll.delete_one({'identifier': identifier})
