from collections.abc import Mapping
from typing import Any, Optional

from eduid.userdb.db import BaseDB, TUserDbDocument

__author__ = "lundberg"


class ScimApiBaseDB(BaseDB):
    def _get_documents_and_count_by_filter(
        self,
        spec: Mapping[str, Any],
        fields: Optional[dict[str, Any]] = None,
        limit: Optional[int] = None,
        skip: Optional[int] = None,
    ) -> tuple[list[TUserDbDocument], int]:
        """
        Locate and count documents in the db using a custom search filter.

        :param spec: the search filter
        :param fields: the fields to return in the search response
        :param skip: Number of documents to skip before returning response
        :param limit: Limit documents returned to this number
        :return: A list of documents and total number of documents matching the query
        :raise DocumentDoesNotExist: No document matching the search criteria
        """
        total_count = self.db_count(spec=spec)
        docs = self._get_documents_by_filter(spec=spec, fields=fields, limit=limit, skip=skip)
        # Correct total_count if it is obviously wrong due to being made before actual data query
        num_docs = len(docs)
        if limit is None or num_docs < limit:
            # Either we got all the documents in hand, or we are on the last 'page' of the series
            total_count = num_docs
            if skip is not None:
                total_count += skip
        return docs, total_count

    def _get_mongo_operator(self, scim_operator: str) -> str:
        # map SCIM filter operators to mongodb filter operator
        mongo_operator = {"eq": "$eq", "gt": "$gt", "ge": "$gte"}.get(scim_operator)
        if not mongo_operator:
            raise ValueError("Invalid filter operator")
        return mongo_operator
