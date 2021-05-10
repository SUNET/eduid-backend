from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Mapping, Optional
from urllib.parse import urlencode

from pydantic import BaseModel

from eduid.webapp.common.session.namespaces import SAMLData

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


class ExternalMfaData(BaseModel):
    """
    Data about a successful external authentication as a multi factor.
    """

    issuer: str
    authn_context: str
    timestamp: datetime

    def to_session_dict(self) -> Dict[str, Any]:
        return self.dict()

    @classmethod
    def from_session_dict(cls, data: Mapping[str, Any]):
        return cls(**data)


@dataclass
class SSOLoginData:
    """
    Class to hold data about an ongoing login process in memory only.

    Instances of this class is used more or less like a context being passed around.
    None of this data is persisted anywhere.

    The 'key' represents the SAML request and associated information, and can be used
    to fetch that data from the EduidSession.
    """

    key: str

    # Hash from Credential.key to datetime when it was used
    mfa_action_creds: Dict[str, datetime] = field(default_factory=dict, init=False, repr=False)
    mfa_action_external: Optional[ExternalMfaData] = field(default=None, init=False, repr=False)

    # When this is non-zero, a message is shown to the user by the
    # login page template saying username/pw was incorrect.
    FailCount: int = 0

    # SAML request, loaded lazily from the session using `key'
    # eduid.webapp.common can't import from eduid-webapp
    _saml_data: Optional[SAMLData] = field(default=None, init=False, repr=False)
    _saml_req: Optional['IdP_SAMLRequest'] = field(default=None, init=False, repr=False)

    def __str__(self) -> str:
        return f'<{self.__class__.__name__}: key={self.key}>'

    @property
    def saml_data(self) -> SAMLData:
        if self._saml_data is None:
            from eduid.webapp.common.session import session

            for _uuid, this in session.idp.pending_requests.items():
                if this.key == self.key:
                    self._saml_data = this
                    return this
            raise RuntimeError(f'SAML data with key {self.key} not found in session')
        return self._saml_data

    @property
    def SAMLRequest(self) -> str:
        if not isinstance(self.saml_data.request, str):
            raise ValueError('saml_data.request not initialised')
        return self.saml_data.request

    @property
    def RelayState(self) -> str:
        if not isinstance(self.saml_data.relay_state, str):
            raise ValueError('saml_data.relay_state not initialised')
        return self.saml_data.relay_state

    @property
    def binding(self) -> str:
        if not isinstance(self.saml_data.binding, str):
            raise ValueError('saml_data.binding not initialised')
        return self.saml_data.binding

    @property
    def query_string(self) -> str:
        qs = {'SAMLRequest': self.SAMLRequest, 'RelayState': self.RelayState}
        return urlencode(qs)

    @property
    def saml_req(self) -> 'IdP_SAMLRequest':
        if self._saml_req is None:
            raise ValueError('SSOLoginData.saml_req accessed uninitialised')
        return self._saml_req

    @saml_req.setter
    def saml_req(self, value: Optional['IdP_SAMLRequest']):
        self._saml_req = value
