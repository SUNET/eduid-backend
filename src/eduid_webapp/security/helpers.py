# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import current_app
from eduid_userdb.u2f import U2F
from eduid_webapp.security.schemas import ConvertRegisteredKeys

__author__ = 'lundberg'


def credentials_to_registered_keys(user_u2f_tokens):
    """
    :param user_u2f_tokens: List of users U2F credentials
    :type user_u2f_tokens: eduid_userdb.credentials.CredentialList

    :return: List of registered keys
    :rtype: list
    """
    u2f_dicts = user_u2f_tokens.to_list_of_dicts()
    return ConvertRegisteredKeys().dump({'registered_keys': u2f_dicts}).data['registered_keys']


def compile_credential_list(security_user):
    """
    :param security_user: User
    :type security_user: eduid_userdb.security.SecurityUser
    :return: List of augmented credentials
    :rtype: list
    """
    credentials = []
    authn_info = current_app.authninfo_db.get_authn_info(security_user)
    for credential in security_user.credentials.to_list():
        credential_dict = credential.to_dict()
        credential_dict['key'] = credential.key
        credential_dict.update(authn_info[credential.key])
        credentials.append(credential_dict)
    return credentials


def remove_nin_from_user(security_user, nin):
    """
    :param security_user: Private userdb user
    :param nin: NIN to remove

    :type security_user: eduid_userdb.security.SecurityUser
    :type nin: str

    :return: None
    """
    if security_user.nins.find(nin):
        security_user.nins.remove(nin)
        security_user.modified_ts = True
        # Save user to private db
        current_app.private_userdb.save(security_user, check_sync=False)
        # Ask am to sync user to central db
        current_app.logger.debug('Request sync for user {!s}'.format(security_user))
        result = current_app.am_relay.request_user_sync(security_user)
        current_app.logger.info('Sync result for user {!s}: {!s}'.format(security_user, result))
    else:
        current_app.logger.info("Can't remove NIN - NIN not found")
        current_app.logger.info("NIN: {}".format(nin))
