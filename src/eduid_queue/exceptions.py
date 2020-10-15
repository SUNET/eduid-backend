# -*- coding: utf-8 -*-

from eduid_userdb.exceptions import EduIDDBError

__author__ = 'lundberg'


class PayloadNotRegistered(EduIDDBError):
    """
    Exception when a payload is not registered with a QueueDB.
    """

    pass
