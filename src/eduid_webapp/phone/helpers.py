# -*- coding: utf-8 -*-

from functools import wraps

from flask import current_app, session

from eduid_userdb import User
from eduid_userdb.proofing import ProofingUser
from eduid_userdb.exceptions import UserDoesNotExist, MultipleUsersReturned
from eduid_common.api.utils import retrieve_modified_ts, get_user
from eduid_common.api.exceptions import ApiException


def require_user(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_user(current_app.phone_proofing_userdb)
        kwargs['user'] = user
        return f(*args, **kwargs)
    return decorated_function


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
