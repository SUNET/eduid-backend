# -*- coding: utf-8 -*-

from flask import current_app, session

from eduid_userdb import User
from eduid_userdb.proofing import ProofingUser
from eduid_userdb.exceptions import UserDoesNotExist, MultipleUsersReturned
from eduid_common.api.utils import retrieve_modified_ts
from eduid_common.api.exceptions import ApiException


def get_user():
    eppn = session.get('user_eppn', None)
    if not eppn:
        raise ApiException('Not authorized', status_code=401)
    # Get user from central database
    try:
        user = current_app.central_userdb.get_user_by_eppn(eppn, raise_on_missing=True)
        proofing_user = ProofingUser(data = user.to_dict())
        retrieve_modified_ts(proofing_user, current_app.phone_proofing_userdb)
        return proofing_user
    except UserDoesNotExist as e:
        current_app.logger.error('Could not find user central database.')
        current_app.logger.error(e)
        raise ApiException('Not authorized', status_code=401)
    except MultipleUsersReturned as e:
        current_app.logger.error('Found multiple users in central database.')
        current_app.logger.error(e)
        raise ApiException('Not authorized', status_code=401)


def save_user(user):
    """
    Save (new) user objects to the db in the new format,
    and propagate the changes to the central user db.

    May raise UserOutOfSync exception

    :param user: the modified user
    :type user: eduid_userdb.ProofingUser
    """
    if isinstance(user, User) and not isinstance(user, ProofingUser):
        # turn it into a ProofingUser before saving it in the dashboard private db
        user = ProofingUser(data = user.to_dict())
    current_app.phone_proofing_userdb.save(user)
    return current_app.am_relay.request_user_sync(user)
