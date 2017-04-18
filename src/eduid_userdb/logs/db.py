# -*- coding: utf-8 -*-

from eduid_userdb.db import BaseDB
import logging

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


class LogDB(BaseDB):

    def __init__(self, db_uri, collection):
        db_name = 'eduid_logs'
        BaseDB.__init__(self, db_uri, db_name, collection)

    def _insert(self, doc):
        self._coll.insert(doc, safe=True)  # Make sure the write succeeded

    def save(self, log_element):
        """
        @param log_element:
        @type log_element: eduid_userdb.logs.element.LogElement
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
