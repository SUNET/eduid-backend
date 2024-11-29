"""
Exceptions thrown by the eduid.userdb database lookup functions.
"""


class EduIDDBError(Exception):
    """
    eduID userdb Exception class.

    :param reason: Reason for exception (typically a string)
    :type reason: object
    """

    def __init__(self, reason: object) -> None:
        Exception.__init__(self)
        self.reason = reason

    def __str__(self) -> str:
        return f"<{self.__class__.__name__} instance at {hex(id(self))}: {self.reason!r}>"


class ConnectionError(EduIDDBError):
    """
    Error connecting to the database.
    """


class MongoConnectionError(ConnectionError):
    """
    Error connecting to MongoDB.
    """


class DocumentDoesNotExist(EduIDDBError):
    pass


class UserDoesNotExist(DocumentDoesNotExist):
    """
    Requested user could not be found in the database.
    """


class MultipleDocumentsReturned(EduIDDBError):
    pass


class MultipleUsersReturned(MultipleDocumentsReturned):
    """
    More than one user in the database matched the given search criteria.
    """


class EduIDUserDBError(EduIDDBError):
    """
    eduID userdb Exception class.
    """


class UserHasUnknownData(EduIDUserDBError):
    """
    One or more elements of the user could not be interpreted.
    """


class UserDBValueError(EduIDUserDBError):
    """
    Error regarding APIAuthUser instances.
    """


class UserMissingData(EduIDUserDBError):
    """
    There is missing data for a User
    """


class DocumentOutOfSync(EduIDDBError):
    """
    The document has been modified since it was read from the db.
    """


class LockedIdentityViolation(EduIDUserDBError):
    """
    The user is trying to verify an identity that differs from the current locked identity.
    """


class UserOutOfSync(DocumentOutOfSync):
    """
    The user has been modified since it was read from the db.
    """


class UserIsRevoked(EduIDUserDBError):
    """
    The user has been permanently deleted from eduID.

    The only things remaining are the _id and eppn, as placeholders to make sure
    they are never ever re-used (Kantara requirement).
    """


class UserHasNotCompletedSignup(EduIDUserDBError):
    """
    The user has not completed the Signup process.

    Signup has created lots of users in the database with only eppn, mail and mailAliases.
    """


class ActionDBError(EduIDUserDBError):
    """
    There was an actions-database related error
    """


class BadEvent(EduIDUserDBError):
    """
    General error in Event processing.
    """


class EventHasUnknownData(BadEvent):
    """
    One or more elements of the event could not be interpreted.
    """
