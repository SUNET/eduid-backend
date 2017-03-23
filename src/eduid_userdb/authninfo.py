# -*- coding: utf-8 -*-

from __future__ import absolute_import

from bson import ObjectId
import logging

from eduid_userdb.userdb import BaseDB
from eduid_userdb.util import convert_to_localtime

logger = logging.getLogger(__name__)

__author__ = 'eperez'


class AuthnInfoDB(BaseDB):

    def __init__(self, db_uri,
            db_name = 'eduid_idp_authninfo', collection = 'authn_info'):
        super(AuthnInfoDB, self).__init__(db_uri, db_name, collection)

    def get_authn_info(self, user):
        """
        :param user: User object
        :type user: eduid_userdb.user.User
        :return: (type, created_ts, success_ts) for each user credential
        :rtype: list of dicts
        """
        authninfo = []
        for credential in user.passwords.to_list_of_dicts():
            auth_entry = self._coll.find_one({'_id': ObjectId(credential['id'])})
            logger.debug("get_authn_info {!s}: cred id: {!r} auth entry: {!r}".format(user, credential['id'], auth_entry))
            if auth_entry:
                created_dt = convert_to_localtime(credential['created_ts'])
                success_dt = convert_to_localtime(auth_entry['success_ts'])
                data_type = 'security.password_credential_type'
                data = {'credential_type': data_type,
                        'created_ts': created_dt.strftime('%Y-%b-%d %H:%M'),
                        'success_ts': success_dt.strftime('%Y-%b-%d %H:%M')}
                authninfo.append(data)
        return authninfo
