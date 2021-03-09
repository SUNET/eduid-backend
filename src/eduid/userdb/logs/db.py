# -*- coding: utf-8 -*-

import logging

from eduid.userdb.db import BaseDB

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


class LogDB(BaseDB):
    def __init__(self, db_uri, collection):
        db_name = 'eduid_logs'
        # Make sure writes reach a majority of replicas
        BaseDB.__init__(self, db_uri, db_name, collection, safe_writes=True)

    def _insert(self, doc):
        self._coll.insert_one(doc)

    def save(self, log_element):
        """
        @param log_element:
        @type log_element: eduid.userdb.logs.element.LogElement
        @return: Boolean
        @rtype: bool
        """
        if log_element.validate():
            self._insert(log_element.to_dict())
            return True
        return False


class ProofingLog(LogDB):
    def __init__(self, db_uri, collection='proofing_log'):
        LogDB.__init__(self, db_uri, collection)
