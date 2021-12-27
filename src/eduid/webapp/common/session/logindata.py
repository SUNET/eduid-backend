from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, TYPE_CHECKING
from urllib.parse import urlencode

from pydantic import BaseModel

from eduid.webapp.common.session.namespaces import IdP_PendingRequest, IdP_SAMLPendingRequest, RequestRef

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


@dataclass
class LoginContext:
    """
    Class to hold data about an ongoing login process in memory only.

    Instances of this class is used more or less like a context being passed around.
    None of this data is persisted anywhere.

    The 'request_ref' can be used to fetch information about this pending request from the EduidSession.
    """

    request_ref: RequestRef

    # SAML request, loaded lazily from the session using `key'
    # eduid.webapp.common can't import from eduid-webapp
    _saml_data: Optional[IdP_SAMLPendingRequest] = field(default=None, init=False, repr=False)
    _saml_req: Optional['IdP_SAMLRequest'] = field(default=None, init=False, repr=False)
    _request_ref: Optional[RequestRef] = field(default=None, init=False, repr=False)

    def __str__(self) -> str:
        return f'<{self.__class__.__name__}: key={self.request_ref}>'

    @property
    def pending_request(self) -> IdP_PendingRequest:
        if self._saml_data is None:
            from eduid.webapp.common.session import session

            saml_data = session.idp.pending_requests.get(self.request_ref)
            if not saml_data:
                raise RuntimeError(f'SAML data with ref {self.request_ref} not found in session')
            self._saml_data = saml_data

        return self._saml_data

    @property
    def SAMLRequest(self) -> str:
        pending = self.pending_request
        if not isinstance(pending, IdP_SAMLPendingRequest):
            raise ValueError('Pending request not initialised')
        if not isinstance(pending.request, str):
            raise ValueError('saml_data.request not initialised')
        return pending.request

    @property
    def RelayState(self) -> str:
        if not self.pending_request.relay_state:
            return ''
        return self.pending_request.relay_state

    @property
    def binding(self) -> str:
        if not isinstance(self.pending_request.binding, str):
            raise ValueError('saml_data.binding not initialised')
        return self.pending_request.binding

    @property
    def query_string(self) -> str:
        qs = {'SAMLRequest': self.SAMLRequest, 'RelayState': self.RelayState}
        return urlencode(qs)

    @property
    def saml_req(self) -> 'IdP_SAMLRequest':
        # TODO: saml_req is a sort of layering violation. It is basically the same as SAMLRequest (from this object)
        #       plus a reference to the pysaml2 IDP instance. Replace with LoginContext.SAMLRequest.

        # avoid circular import
        from eduid.webapp.idp.app import current_idp_app as current_app
        from eduid.webapp.idp.idp_saml import IdP_SAMLRequest

        return IdP_SAMLRequest(self.SAMLRequest, self.binding, current_app.IDP, debug=current_app.conf.debug)
        # if self._saml_req is None:
        #    raise ValueError('SSOLoginData.saml_req accessed uninitialised')
        # return self._saml_req

    @saml_req.setter
    def saml_req(self, value: Optional['IdP_SAMLRequest']):
        # self._saml_req = value
        pass
