from __future__ import annotations

import pprint
from dataclasses import asdict, dataclass, field
from datetime import datetime
from html import escape
from typing import TYPE_CHECKING, Any, Dict, Mapping, Optional, Type
from urllib.parse import urlencode

from eduid.userdb.credentials import Credential

from eduid.common.session.namespaces import SessionNSBase

if TYPE_CHECKING:
    from eduid.webapp.idp.idp_saml import IdP_SAMLRequest

#
# Copyright (c) 2013, 2014, 2016 NORDUnet A/S. All rights reserved.
# Copyright 2012 Roland Hedberg. All rights reserved.
#
# See the file eduid-IdP/LICENSE.txt for license statement.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#          Roland Hedberg
#


@dataclass
class ExternalMfaData(object):
    """
    Data about a successful external authentication as a multi factor.
    """

    issuer: str
    authn_context: str
    timestamp: datetime

    def to_session_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_session_dict(cls, data: Dict[str, Any]):
        return cls(**data)


@dataclass
class SSOLoginData(SessionNSBase):
    """
    Class to hold data about an ongoing login process - i.e. data relating to a
    particular IdP visitor in the process of logging in, but not yet fully logged in.

    :param key: Unique reference for this instance.
    :param SAMLRequest: SAML request.
    :param binding: SAML binding
    :param RelayState: This is an opaque string generated by a SAML SP that must be
                        sent to the SP when the authentication is finished and the
                        user redirected to the SP.
    :param FailCount: The number of failed login attempts. Used to show an alert
                      message to the user to make them aware of the reason they got
                      back to the IdP login page.
    """

    key: str
    SAMLRequest: str
    binding: str
    RelayState: str = ''
    FailCount: int = 0

    # saml request object
    # eduid-common can't import from eduid-webapp
    saml_req: 'IdP_SAMLRequest' = field(init=False, repr=False)

    # query string
    query_string: str = field(init=False, repr=False)

    # Hash from Credential.key to datetime when it was used
    mfa_action_creds: Dict[str, datetime] = field(default_factory=dict, init=False, repr=False)
    mfa_action_external: Optional[ExternalMfaData] = field(default=None, init=False, repr=False)

    def __post_init__(self):
        self.key = escape(self.key, quote=True)
        self.RelayState = escape(self.RelayState, quote=True)
        self.SAMLRequest = escape(self.SAMLRequest, quote=True)
        self.binding = escape(self.binding, quote=True)
        qs = {'SAMLRequest': self.SAMLRequest, 'RelayState': self.RelayState}
        self.query_string = urlencode(qs)

    def to_dict(self) -> Dict[str, str]:
        return {
            'key': self.key,
            'SAMLRequest': self.SAMLRequest,
            'RelayState': self.RelayState,
            'binding': self.binding,
            'FailCount': str(self.FailCount),
        }

    @classmethod
    def from_dict(cls: Type[SSOLoginData], data: Mapping[str, str]) -> SSOLoginData:
        key = data['key']
        SAMLRequest = data['SAMLRequest']
        RelayState = data['RelayState']
        binding = data['binding']
        FailCount = int(data['FailCount'])
        return cls(key, SAMLRequest, binding, RelayState, FailCount)

    def __str__(self) -> str:
        try:
            data = self.to_dict()
        except AttributeError:
            return f'<Unprintable SSOLoginData: key={self.key}>'
        if 'SAMLRequest' in data:
            data['SAMLRequest length'] = str(len(data['SAMLRequest']))
            del data['SAMLRequest']
        return pprint.pformat(data)
