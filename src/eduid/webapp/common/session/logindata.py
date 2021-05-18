from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Mapping, Optional
from urllib.parse import urlencode

from pydantic import BaseModel

from eduid.webapp.common.session.namespaces import IdP_PendingRequest, ReqSHA1, RequestRef

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

    key: ReqSHA1

    # SAML request, loaded lazily from the session using `key'
    # eduid.webapp.common can't import from eduid-webapp
    _saml_data: Optional[IdP_PendingRequest] = field(default=None, init=False, repr=False)
    _saml_req: Optional['IdP_SAMLRequest'] = field(default=None, init=False, repr=False)
    _request_ref: Optional[RequestRef] = field(default=None, init=False, repr=False)

    def __str__(self) -> str:
        return f'<{self.__class__.__name__}: key={self.key}>'

    @property
    def request_ref(self) -> RequestRef:
        if self._request_ref is None:
            from eduid.webapp.common.session import session

            req_ref = session.idp.get_requestref_for_reqsha1(self.key)
            if not req_ref:
                raise RuntimeError(f'Request with key {self.key} not found in session')
            self._request_ref = req_ref

        return self._request_ref

    @property
    def saml_data(self) -> IdP_PendingRequest:
        if self._saml_data is None:
            from eduid.webapp.common.session import session

            saml_data = session.idp.pending_requests[self.request_ref]
            if not saml_data:
                raise RuntimeError(f'SAML data with ref {self.request_ref} not found in session')
            self._saml_data = saml_data

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
