from eduid_userdb.db import MongoDB
from datetime import datetime
from time import time


class CacheMDB():
    _init_collections = {}

    def __init__(self, mongo_dburi, mongo_dbname, mongo_collection, ttl, expiration_freq=60):
        self.conn = MongoDB(mongo_dburi)
        self.db = self.conn.get_database(mongo_dbname)
        self.collection = self.db[mongo_collection]
        self._expiration_freq = expiration_freq
        self._last_expire_at = None
        self._ttl = ttl
        self.ensure_indices(mongo_collection)

    def add_cache_item(self, identifier, data):
        date = datetime.fromtimestamp(time(), None)
        doc = {'identifier': identifier,
               'data': data,
               'created_at': date}
        self.collection.insert(doc)
        self.expire_cache_items()
        return True

    def get_cache_item(self, identifier):
        query = {'identifier': identifier}
        result = self.collection.find_one(query)
        if result is not None:
            return result['data']
        return result

    def get_cached_items_by_query(self, query):
        result = self.collection.find(query)
        return result

    def update_cache_item(self, identifier, data):
        date = datetime.fromtimestamp(time(), None)
        return self.collection.update({'identifier': identifier}, {'$set': {'data': data, 'updated_at': date}}, w=1,
                                      getLastError=True)

    def remove_cache_item(self, identifier):
        return self.collection.remove({'identifier': identifier}, w=1, getLastError=True)

    def expire_cache_items(self, force=False):
        ts = time() - self._ttl
        if not force and (self._last_expire_at > ts - self._expiration_freq):
            return False
        self._last_expire_at = ts
        date = datetime.fromtimestamp(ts, None)
        self.collection.remove({'created_at': {'$lt': date}}, w=1)
        return True

    def ensure_indices(self, collection):
        if collection not in self._init_collections:  # Only ensure indices once
            self._init_collections[collection] = 1
            self.db[collection].ensure_index('created_at', name='created_at_idx', unique=False)
            self.db[collection].ensure_index('identifier', name='identifier_idx', unique=True)
