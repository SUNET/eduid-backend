# -*- coding: utf-8 -*-

from __future__ import absolute_import

import copy
import bson
import datetime
import logging
from eduid_userdb.db import BaseDB
from eduid_userdb.exceptions import UserHasUnknownData, DocumentOutOfSync, DocumentDoesNotExist

__author__ = 'lundberg'

# Store all data received from the op


class Proof(object):
    def __init__(self, data, raise_on_unknown=True):
        self._data_in = copy.deepcopy(data)  # to not modify callers data
        self._data = dict()

        # things without setters
        # _id
        _id = self._data_in.pop('_id', None)
        if _id is None:
            _id = bson.ObjectId()
        if not isinstance(_id, bson.ObjectId):
            _id = bson.ObjectId(_id)
        self._data['_id'] = _id
        # eppn
        eppn = self._data_in.pop('eduPersonPrincipalName')
        self._data['eduPersonPrincipalName'] = eppn

        # authn_resp
        authn_resp = self._data_in.pop('authn_resp')
        self._data['authn_resp'] = authn_resp

        # token_resp
        token_resp = self._data_in.pop('token_resp')
        self._data['token_resp'] = token_resp

        # userinfo
        userinfo = self._data_in.pop('userinfo')
        self._data['userinfo'] = userinfo

        self.modified_ts = self._data_in.pop('modified_ts', None)

        if len(self._data_in) > 0:
            if raise_on_unknown:
                raise UserHasUnknownData('User {!s} unknown data: {!r}'.format(
                    self.eppn, self._data_in.keys()
                ))
            # Just keep everything that is left as-is
            self._data.update(self._data_in)

    def __repr__(self):
        return '<eduID {!s}: {!s}>'.format(self.__class__.__name__, self.eppn)

    @property
    def _id(self):
        """
        Get the vetting datas _id

        :rtype: bson.ObjectId
        """
        return self._data['_id']

    @property
    def eppn(self):
        """
        Get the user's eppn

        :rtype: str | unicode
        """
        return self._data['eduPersonPrincipalName']

    @property
    def auth_resp(self):
        """
        Get the user's auth_resp

        :rtype: dict
        """
        return self._data['auth_resp']

    @property
    def token_resp(self):
        """
        Get the user's token_resp

        :rtype: dict
        """
        return self._data['token_resp']

    @property
    def userinfo(self):
        """
        Get the user's userinfo

        :rtype: dict
        """
        return self._data['userinfo']

    @property
    def modified_ts(self):
        """
        :return: Timestamp of last modification in the database.
                 None if User has never been written to the database.
        :rtype: datetime.datetime | None
        """
        return self._data.get('modified_ts')

    @modified_ts.setter
    def modified_ts(self, value):
        """
        :param value: Timestamp of modification.
                      Value None is ignored, True is short for datetime.utcnow().
        :type value: datetime.datetime | True | None
        """
        if value is None:
            return
        if value is True:
            value = datetime.datetime.utcnow()
        self._data['modified_ts'] = value

    def to_dict(self):
        res = copy.copy(self._data)  # avoid caller messing with our _data
        return res


class ProofDB(BaseDB):

    ProofDataClass = Proof

    def __init__(self, db_uri, db_name='eduid_oidc_proofing', collection='proofs'):
        BaseDB.__init__(self, db_uri, db_name, collection)

    def get_proofs_by_eppn(self, eppn, raise_on_missing=True):
        """
        Locate a vetting data in the db given the user's eppn.

        :param eppn: eppn
        :param raise_on_missing: Raise exception if True else return None

        :type eppn: str | unicode
        :type raise_on_missing: bool

        :return: VettingDataClass instance | None
        :rtype: VettingDataClass | None

        :raise self.DocumentDoesNotExist: No user match the search criteria
        """

        data = self._get_documents_by_attr('eduPersonPrincipalName', eppn, raise_on_missing)
        return [self.ProofDataClass(item) for item in data]

    def save(self, proof, check_sync=True):
        """

        :param proof: VettingDataClass object
        :param check_sync: Ensure the document hasn't been updated in the database since it was loaded

        :type proof: VettingDataClass
        :type check_sync: bool

        :return:
        """

        modified = proof.modified_ts
        proof.modified_ts = True  # update to current time
        if modified is None:
            # document has never been modified
            result = self._coll.insert(proof.to_dict())
            logging.debug("{!s} Inserted new state {!r} into {!r}): {!r})".format(
                self, proof, self._coll_name, result))
        else:
            test_doc = {'_id': proof._id}
            if check_sync:
                test_doc['modified_ts'] = modified
            result = self._coll.update(test_doc, proof.to_dict(), upsert=(not check_sync))
            if check_sync and result['n'] == 0:
                db_ts = None
                db_state = self._coll.find_one({'_id': proof._id})
                if db_state:
                    db_ts = db_state['modified_ts']
                logging.debug("{!s} FAILED Updating state {!r} (ts {!s}) in {!r}). "
                              "ts in db = {!s}".format(self, proof, modified, self._coll_name, db_ts))
                raise DocumentOutOfSync('Stale state object can\'t be saved')
            logging.debug("{!s} Updated state {!r} (ts {!s}) in {!r}): {!r}".format(
                self, proof, modified, self._coll_name, result))
