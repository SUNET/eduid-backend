import logging
from dataclasses import dataclass, replace
from typing import Any, Dict

from bson import ObjectId

from eduid_userdb.db import BaseDB

from eduid_groupdb import Group
from eduid_groupdb.group import GroupAttrs

__author__ = 'ft'

logger = logging.getLogger(__name__)


class AttributeDB(BaseDB):
    def load_attributes(self, group: Group) -> Group:
        test_doc = {
            '_group_identifier': group.identifier,
        }
        docs = self._get_documents_by_filter(spec=test_doc, raise_on_missing=False)
        if not docs:
            return group
        if len(docs) != 1:
            raise RuntimeError(f'More than one set of attributes returned for identifier {group.identifier}')
        attr_dict = docs[0]['data']
        attr_dict['_id'] = docs[0]['_id']
        attrs = GroupAttrs.from_mapping(attr_dict)
        return replace(group, attributes=attrs)

    def save_attributes(self, group: Group) -> Group:
        attr_doc = {
            '_id': group.attributes._id,
            '_group_identifier': group.identifier,
            'data': group.attributes.to_dict(),
        }

        if group.attributes._id is None:
            # attributes never saved before
            del attr_doc['_id']
            res = self._coll.insert_one(attr_doc)
            new_attrs = replace(group.attributes, _id=res.inserted_id)
            return replace(group, attributes=new_attrs)

        # _id is not None, which means it should exist in the database
        test_doc = {
            '_id': group.attributes._id,
            '_group_identifier': group.identifier,
        }
        res = self._coll.replace_one(test_doc, attr_doc, upsert=False)
        if res.matched_count != 1:
            logger.error(f'{self} FAILED Updating attributes {group.attributes} in {self._coll_name}: {res}')
            raise RuntimeError('Group attributes out of sync')
        if res.modified_count != 1:
            logger.debug('The attributes were not modified')

        return group
