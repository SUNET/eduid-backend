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
from datetime import timedelta
from typing import Any, Mapping, Optional

from eduid.userdb.signup import SignupUser
from eduid.userdb.userdb import UserDB

__author__ = "ft"


class SignupUserDB(UserDB[SignupUser]):
    def __init__(
        self,
        db_uri: str,
        db_name: str = "eduid_signup",
        collection: str = "registered",
        auto_expire: Optional[timedelta] = None,
    ):
        super().__init__(db_uri, db_name, collection=collection)

        if auto_expire is not None:
            # auto expire register data
            indexes = {
                "auto-discard-modified-ts": {
                    "key": [("modified_ts", 1)],
                    "expireAfterSeconds": int(auto_expire.total_seconds()),
                },
            }
            self.setup_indexes(indexes)

    @classmethod
    def user_from_dict(cls, data: Mapping[str, Any]) -> SignupUser:
        return SignupUser.from_dict(data)

    def get_user_by_mail_verification_code(self, code: str) -> Optional[SignupUser]:
        return self._get_user_by_attr("pending_mail_address.verification_code", code)

    def get_user_by_pending_mail_address(self, mail: str) -> Optional[SignupUser]:
        mail = mail.lower()
        return self._get_user_by_attr("pending_mail_address.email", mail)
