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

__author__ = 'ft'

from eduid_userdb.userdb import UserDB
from eduid_userdb.signup import SignupUser
from eduid_userdb.exceptions import MultipleUsersReturned


class SignupUserDB(UserDB):

    UserClass = SignupUser

    def __init__(self, db_uri, db_name='eduid_signup', collection='registered'):
        UserDB.__init__(self, db_uri, db_name, collection)

    def get_user_by_mail_verification_code(self, code):
        docs = self._coll.find({'pending_mail_address.verification_code': code})
        users = []
        if docs.count() > 0:
            users = list(docs)
        if not users:
            return None
        elif len(users) > 1:
            raise MultipleUsersReturned("Multiple matching users for code {!r}".format(code))
        return self.UserClass(data=users[0])

    def get_user_by_pending_mail_address(self, mail):
        mail = mail.lower()
        docs = self._coll.find({'pending_mail_address.email': mail})
        users = []
        if docs.count() > 0:
            users = list(docs)
        if not users:
            return None
        elif len(users) > 1:
            raise MultipleUsersReturned("Multiple matching users for pending_mail_address {!r}".format(mail))
        return self.UserClass(data=users[0])
