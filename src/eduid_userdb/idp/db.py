#
# Copyright (c) 2013, 2014, 2015 NORDUnet A/S
#                           2019 SUNET
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
# Author : Fredrik Thulin <fredrik@thulin.net>
#

"""
User and user database module.
"""
from six import string_types
import logging
from typing import Optional

from eduid_userdb import UserDB
from .user import IdPUser


class IdPUserDb(object):
    """
    :param logger: logging logger
    :param config: IdP config
    :param userdb: User database
    """

    def __init__(self, logger: logging.Logger, config: dict, userdb: UserDB = None):
        self.logger = logger
        self.config = config
        if userdb is None:
            userdb = UserDB(config['MONGO_URI'], db_name=config['USERDB_MONGO_DATABASE'], user_class=IdPUser)
        self.userdb = userdb

    def lookup_user(self, username: Optional[str]) -> Optional[IdPUser]:
        """
        Load IdPUser from userdb.

        :param username: string
        :return: user found in database
        """
        _user = None
        if isinstance(username, string_types):
            if '@' in username:
                _user = self.userdb.get_user_by_mail(username.lower(), raise_on_missing=False)
            if not _user:
                _user = self.userdb.get_user_by_eppn(username.lower(), raise_on_missing=False)
        if not _user:
            # username will be ObjectId if this is a lookup using an existing SSO session
            _user = self.userdb.get_user_by_id(username, raise_on_missing=False)
        return _user
