#
# Copyright (c) 2014 NORDUnet A/S
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
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Type

import bson

from eduid_common.misc.timeutil import utc_now
from eduid_common.session.logindata import ExternalMfaData
from eduid_userdb import UserDB
from eduid_userdb.idp import IdPUser, IdPUserDb

from eduid_webapp.idp.idp_authn import AuthnData


@dataclass
class SSOSession:
    """
    Single Sign On sessions are used to remember a previous authentication
    performed, to avoid re-authenticating users for every Service Provider
    they visit.

    The references to 'authn' here are strictly about what kind of Authn
    the user has performed. The resulting SAML AuthnContext is a product
    of this, as well as other policy decisions (such as what ID-proofing
    has taken place, what AuthnContext the SP requested and so on).

    :param user_id: User id, typically MongoDB _id
    :param authn_request_id: SAML request id of request that caused authentication
    :param authn_credentials: Data about what credentials were used to authn
    :param ts: Authentication timestamp, in UTC

    :type user_id: bson.ObjectId | object
    :type authn_ref: object
    :type authn_request_id: string
    :type authn_credentials: None | [AuthnData]
    :type ts: int
    """

    user_id: bson.ObjectId
    authn_request_id: str
    authn_credentials: List[AuthnData]
    idp_user: IdPUser  # extra info - not serialised
    external_mfa: Optional[ExternalMfaData] = None
    authn_timestamp: datetime = field(default_factory=utc_now)

    def __str__(self) -> str:
        return f'<{self.__class__.__name__}: uid={self.user_id}, ts={self.authn_timestamp.isoformat()}>'

    def to_dict(self) -> Dict[str, Any]:
        """ Return the object in dict format (serialized for storing in MongoDB). """
        res = asdict(self)
        res['authn_credentials'] = [x.to_dict() for x in self.authn_credentials]
        if self.external_mfa is not None:
            res['external_mfa'] = self.external_mfa.to_session_dict()
        del res['idp_user']
        return res

    @classmethod
    def from_dict(cls: Type[SSOSession], data: Dict[str, Any], userdb: IdPUserDb) -> SSOSession:
        """ Construct element from a data dict in database format. """

        data = dict(data)  # to not modify callers data
        data['authn_credentials'] = [AuthnData.from_dict(x) for x in data['authn_credentials']]
        if 'external_mfa' in data and data['external_mfa'] is not None:
            data['external_mfa'] = [ExternalMfaData.from_session_dict(x) for x in data['external_mfa']]
        if 'user_id' in data:
            data['idp_user'] = userdb.lookup_user(data['user_id'])
            if not data['idp_user']:
                raise RuntimeError(f'User with id {repr(data["user_id"])} not found')
        return cls(**data)

    @property
    def public_id(self) -> str:
        """
        Return a identifier for this session that can't be used to hijack sessions
        if leaked through a log file etc.
        """
        return f'{self.user_id}.{self.authn_timestamp.timestamp()}'

    @property
    def minutes_old(self) -> int:
        """ Return the age of this SSO session, in minutes. """
        age = (utc_now() - self.authn_timestamp).total_seconds()
        return int(age) // 60

    def add_authn_credential(self, authn: AuthnData) -> None:
        """ Add information about a credential successfully used in this session. """
        if not isinstance(authn, AuthnData):
            raise ValueError(f'data should be AuthnData (not {type(authn)})')
        self.authn_credentials += [authn]
