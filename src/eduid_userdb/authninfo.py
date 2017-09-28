# -*- coding: utf-8 -*-

from __future__ import absolute_import

from bson import ObjectId
import logging

from eduid_userdb.userdb import BaseDB
from eduid_userdb.credentials import Password, U2F

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
        for credential in user.credentials.to_list():
            auth_entry = self._coll.find_one(credential.object_id)
            logger.debug("get_authn_info {!s}: cred id: {!r} auth entry: {!r}".format(
                user, credential.object_id, auth_entry))
            if auth_entry:
                created_dt = credential['created_ts']
                success_dt = auth_entry['success_ts']
                data_type = 'security.unknown_credential_type'
                if isinstance(credential, Password):
                    data_type = 'security.password_credential_type'
                elif isinstance(credential, U2F):
                    data_type = 'security.u2f_credential_type'
                data = {'credential_type': data_type,
                        'created_ts': created_dt.isoformat(),
                        'success_ts': success_dt.isoformat()}
                authninfo.append(data)
        return authninfo
