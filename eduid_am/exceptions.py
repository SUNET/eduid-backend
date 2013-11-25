"""
Exceptions thrown by the eduid_am database lookup functions.
"""

class UserDoesNotExist(Exception):
    """
    Requested user could not be found in the database.
    """
    pass

class MultipleUsersReturned(Exception):
    """
    More than one user in the database matched the given search criteria.
    """
    pass
