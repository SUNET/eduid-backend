# -*- coding: utf-8 -*-
import logging

from eduid.userdb.credentials import U2F, Password, Webauthn
from eduid.userdb.userdb import BaseDB

logger = logging.getLogger(__name__)

__author__ = 'eperez'


class AuthnInfoDB(BaseDB):
    def __init__(self, db_uri, db_name='eduid_idp_authninfo', collection='authn_info'):
        super(AuthnInfoDB, self).__init__(db_uri, db_name, collection)

    def get_authn_info(self, user):
        """
        :param user: User object
        :type user: eduid.userdb.user.User
        :return: {credential.key: {type, created_ts, success_ts}} for each user credential
        :rtype: dict
        """
        authninfo = {}
        for credential in user.credentials.to_list():
            created_ts = credential.created_ts.isoformat()
            success_ts = None
            data_type = 'security.unknown_credential_type'
            if isinstance(credential, Password):
                data_type = 'security.password_credential_type'
            elif isinstance(credential, U2F):
                data_type = 'security.u2f_credential_type'
            elif isinstance(credential, Webauthn):
                data_type = 'security.webauthn_credential_type'

            auth_entry = self._coll.find_one(credential.key)
            logger.debug("get_authn_info {!s}: cred id: {!r} auth entry: {!r}".format(user, credential.key, auth_entry))
            if auth_entry:
                success_ts = auth_entry['success_ts'].isoformat()

            authninfo[credential.key] = {
                'credential_type': data_type,
                'created_ts': created_ts,
                'success_ts': success_ts,
            }
        return authninfo
