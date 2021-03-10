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

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, NewType, Optional, Type

import bson
from bson import ObjectId

from eduid.common.misc.timeutil import utc_now
from eduid.common.session.logindata import ExternalMfaData
from eduid.userdb.idp import IdPUser, IdPUserDb
from eduid.webapp.idp.idp_authn import AuthnData

# A distinct type for session ids
SSOSessionId = NewType('SSOSessionId', bytes)


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
    :param authn_timestamp: Authentication timestamp, in UTC

    # These fields are from the 'outer' scope of the session, and are
    # duplicated here for now. Can't be changed here, since they are removed in to_dict.

    :param created_ts: When the database document was created
    :param eppn: User eduPersonPrincipalName

    """

    user_id: bson.ObjectId  # move away from this - use the eppn instead
    authn_request_id: str
    authn_credentials: List[AuthnData]
    eppn: str
    idp_user: IdPUser = field(repr=False)  # extra info - not serialised
    _id: Optional[ObjectId] = None
    session_id: SSOSessionId = field(default_factory=lambda: create_session_id())
    created_ts: datetime = field(default_factory=utc_now)
    external_mfa: Optional[ExternalMfaData] = None
    authn_timestamp: datetime = field(default_factory=utc_now)

    def __str__(self) -> str:
        return f'<{self.__class__.__name__}: eppn={self.eppn}, ts={self.authn_timestamp.isoformat()}>'

    def to_dict(self) -> Dict[str, Any]:
        """ Return the object in dict format (serialized for storing in MongoDB).

        For legacy reasons, some of the attributes are stored in an 'inner' scope called 'data':

        {
            '_id': ObjectId('5fcde44d56cf512b51f1ac4e'),
            'session_id': b'ZjYzOTcwNWItYzUyOS00M2U1LWIxODQtODMxYTJhZjQ0YzA1',
            'username': 'hubba-bubba',
            'data': {
                'user_id': ObjectId('5fd09748c07041072b237ae0')
                'authn_request_id': 'id-IgHyGTmxBEORfx5NJ',
                'authn_credentials': [
                    {
                        'cred_id': '5fc8b78cbdaa0bf337490db1',
                        'authn_ts': datetime.fromisoformat('2020-09-13T12:26:40+00:00'),
                    }
                ],
                'authn_timestamp': 1600000000,
                'external_mfa': None,
            },
            'created_ts': datetime.fromisoformat('2020-12-07T08:14:05.744+00:00'),
        }
         """
        res = asdict(self)
        res['authn_credentials'] = [x.to_dict() for x in self.authn_credentials]
        if self.external_mfa is not None:
            res['external_mfa'] = self.external_mfa.to_session_dict()
        # Remove extra fields
        del res['idp_user']
        # Use integer format for this in the database until this code (from_dict() below) has been
        # deployed everywhere so we can switch to datetime.
        # TODO: Switch over to datetime.
        res['authn_timestamp'] = int(self.authn_timestamp.timestamp())
        # Store these attributes in an 'inner' scope (called 'data')
        _data = {}
        for this in ['user_id', 'authn_request_id', 'authn_credentials', 'authn_timestamp', 'external_mfa']:
            _data[this] = res.pop(this)
        res['data'] = _data
        # rename 'eppn' to 'username' in the database, for legacy reasons
        res['username'] = res.pop('eppn')
        return res

    @classmethod
    def from_dict(cls: Type[SSOSession], data: Mapping[str, Any], userdb: IdPUserDb) -> SSOSession:
        """ Construct element from a data dict in database format. """

        _data = dict(data)  # to not modify callers data
        if 'data' in _data:
            # move contents from 'data' to top-level of dict
            _data.update(_data.pop('data'))
        _data['authn_credentials'] = [AuthnData.from_dict(x) for x in _data['authn_credentials']]
        if 'external_mfa' in _data and _data['external_mfa'] is not None:
            _data['external_mfa'] = [ExternalMfaData.from_session_dict(x) for x in _data['external_mfa']]
        if 'user_id' in _data:
            _data['idp_user'] = userdb.lookup_user(_data['user_id'])
            if not _data['idp_user']:
                raise RuntimeError(f'User with id {repr(_data["user_id"])} not found')
        # Compatibility code to convert integer format to datetime format. Keep this until nothing writes
        # authn_timestamp as integers, and all the existing sessions have expired.
        # TODO: Remove this code when all sessions in the database have datetime authn_timestamps.
        if isinstance(_data.get('authn_timestamp'), int):
            _data['authn_timestamp'] = datetime.fromtimestamp(_data['authn_timestamp'], tz=timezone.utc)
        # rename 'username' to 'eppn'
        if 'eppn' not in _data:
            _data['eppn'] = _data.pop('username')
        return cls(**_data)

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

        # Store only the latest use of a particular credential.
        _creds: Dict[str, AuthnData] = {x.cred_id: x for x in self.authn_credentials}
        _existing = _creds.get(authn.cred_id)
        # TODO: remove this in the future - don't have to set tz when all SSO sessions without such have expired
        if _existing and _existing.timestamp.tzinfo is None:
            _existing.timestamp = _existing.timestamp.replace(tzinfo=timezone.utc)
        # only replace if newer
        if not _existing or authn.timestamp > _existing.timestamp:
            _creds[authn.cred_id] = authn

        # sort on cred_id to have deterministic order in tests
        _list = list(_creds.values())
        self.authn_credentials = sorted(_list, key=lambda x: x.cred_id)


def create_session_id() -> SSOSessionId:
    """
    Create a unique value suitable for use as session identifier.

    The uniqueness and inability to guess is security critical!
    :return: session_id as bytes (to match what cookie decoding yields)
    """
    return SSOSessionId(bytes(str(uuid.uuid4()), 'ascii'))
