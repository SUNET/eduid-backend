"""
Exceptions thrown by the eduid_userdb database lookup functions.
"""


class EduIDUserDBError(Exception):
    """
    eduID userdb Exception class.

    :param reason: Reason for exception (typically a string)
    :type reason: object
    """
    def __init__(self, reason):
        Exception.__init__(self)
        self.reason = reason

    def __str__(self):
        return '<{cl} instance at {addr}: {reason!r}>'.format(
            cl = self.__class__.__name__,
            addr = hex(id(self)),
            reason = self.reason,
        )


class UserHasUnknownData(EduIDUserDBError):
    """
    One or more elements of the user could not be interpreted.
    """
    pass


class UserDBValueError(EduIDUserDBError):
    """
    Error regarding APIAuthUser instances.
    """
    pass


class UserDoesNotExist(EduIDUserDBError):
    """
    Requested user could not be found in the database.
    """
    pass


class MultipleUsersReturned(EduIDUserDBError):
    """
    More than one user in the database matched the given search criteria.
    """
    pass


class UserOutOfSync(EduIDUserDBError):
    """
    The user has been modified since it was read from the db.
    """
    pass
