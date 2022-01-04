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
import logging
from typing import Any, Mapping, Optional

from eduid.userdb import UserDB
from eduid.userdb.exceptions import EduIDDBError
from eduid.userdb.idp.user import IdPUser

logger = logging.getLogger(__name__)


class IdPUserDb(UserDB[IdPUser]):
    def __init__(self, db_uri: str, db_name: str = 'eduid_idp', collection: str = 'profiles'):
        super().__init__(db_uri, db_name, collection=collection)

    @classmethod
    def user_from_dict(cls, data: Mapping[str, Any]) -> IdPUser:
        return IdPUser.from_dict(data)

    def lookup_user(self, username: str) -> Optional[IdPUser]:
        """
        Load IdPUser from userdb.

        :param username: Either an e-mail address or an eppn.
        :return: user found in database
        """
        user = None
        try:
            if '@' in username:
                user = self.get_user_by_mail(username.lower())
            if not user:
                user = self.get_user_by_eppn(username.lower())
        except EduIDDBError as exc:
            logger.warning(f'User lookup using {repr(username)} did not return a valid user: {str(exc)}')
            return None

        if not user:
            logger.info(f'Unknown user: {repr(username)}')
            return None

        logger.debug(f'Found user {user} using {repr(username)}')
        return user
