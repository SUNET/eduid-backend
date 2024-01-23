from eduid.queue.db import QueueDB

__author__ = "lundberg"


class TestDB(QueueDB):
    def __init__(self, db_uri: str, collection: str = "test"):
        super().__init__(db_uri, collection=collection)


class MessageDB(QueueDB):
    def __init__(self, db_uri: str, collection: str = "message"):
        super().__init__(db_uri, collection=collection)
