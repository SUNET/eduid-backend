# -*- coding: utf-8 -*-


from eduid_webapp.support.app import current_support_app as current_app

__author__ = 'lundberg'


def get_credentials_aux_data(user):
    """
    :param user: User object
    :type user: eduid_userdb.user.User
    :return: Augmented credentials list
    :rtype: list
    """
    credentials = []
    for credential in user.credentials.to_list():
        credential_dict = credential.to_dict()
        credential_info = current_app.support_authn_db.get_credential_info(credential.key)
        if credential_info:
            # Add success_ts
            credential_dict['success_ts'] = credential_info['success_ts']
        credentials.append(credential_dict)
    return credentials
