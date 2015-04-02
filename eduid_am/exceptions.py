"""
Exceptions thrown by the eduid_am database lookup functions.
"""

# Import these here so that users of eduid-am doesn't have to know about the
# underlying database being used.

# XXX this might be unnecessary now that eduid-userdb is a proper stand-alone
# module.

from eduid_userdb.exceptions import UserDoesNotExist, MultipleUsersReturned, UserOutOfSync
