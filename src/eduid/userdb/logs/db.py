# -*- coding: utf-8 -*-

import logging

from eduid.userdb.db import BaseDB

__author__ = 'lundberg'

from eduid.userdb.logs.element import LogElement

logger = logging.getLogger(__name__)


class LogDB(BaseDB):
    def __init__(self, db_uri, collection):
        db_name = 'eduid_logs'
        # Make sure writes reach a majority of replicas
        BaseDB.__init__(self, db_uri, db_name, collection, safe_writes=True)

    def _insert(self, doc):
        self._coll.insert_one(doc)

    def save(self, log_element: LogElement) -> bool:
        """
        :param log_element: The log element to save
        :return: True on success
        """
        self._insert(log_element.to_dict())
        return True


class ProofingLog(LogDB):
    def __init__(self, db_uri, collection='proofing_log'):
        LogDB.__init__(self, db_uri, collection)
