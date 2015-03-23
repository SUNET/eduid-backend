#
# Copyright (c) 2015 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

from eduid_userdb.db import MongoDB
import eduid_userdb.exceptions
from eduid_userdb.exceptions import UserDoesNotExist, MultipleUsersReturned

import logging
logger = logging.getLogger(__name__)


class UserDB(object):
    """
    Interface class to the central eduID UserDB.
    """

    def __init__(self, db_uri, collection='userdb'):

        self._db = MongoDB(db_uri)
        self._coll = self._db.get_collection(collection)
        # XXX Backwards compatibility.
        # Was: provide access to our backends exceptions to users of this class
        self.exceptions = eduid_userdb.exceptions

    def get_user_by_mail(self, email, raise_on_missing=False, include_unconfirmed=False):
        """
        Return the user object in the central eduID UserDB having
        an email address matching `email'. Unless include_unconfirmed=True, the
        email address has to be confirmed/verified.

        :param email: The email address to look for
        :param raise_on_missing: If True, raise exception if no matching user object can be found.
        :param include_unconfirmed: Require email address to be confirmed/verified.

        :type email: str | unicode
        :type raise_on_missing: bool
        :type include_unconfirmed: bool
        :return: A user dict
        :rtype: eduid_userdb.User
        """
        email = email.lower()
        elemmatch = {'email': email, 'verified': True}
        if include_unconfirmed:
            elemmatch = {'email': email}
        # XXX this only looks in the legacy collection, in the legacy format
        docs = self._coll.find(
            {'$or': [
                {'mail': email},
                {'mailAliases': {'$elemMatch': elemmatch}}
            ]})
        users = []
        if docs.count() > 0:
            users = list(docs)
        if not users:
            if raise_on_missing:
                raise UserDoesNotExist("No user matching email {!r}".format(email))
            return None
        elif len(users) > 1:
            raise MultipleUsersReturned("Multiple matching users for email {!r}".format(email))
        return users[0]
