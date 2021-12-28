from __future__ import annotations

from abc import ABC
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, TypeVar
from urllib.parse import urlencode

from pydantic import BaseModel

from eduid.webapp.common.session.namespaces import (
    IdP_OtherDevicePendingRequest,
    IdP_PendingRequest,
    IdP_SAMLPendingRequest,
    RequestRef,
)
from eduid.webapp.idp.idp_saml import IdP_SAMLRequest
from eduid.webapp.idp.other_device import OtherDevice


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
class LoginContext(ABC):
    """
    Class to hold data about an ongoing login process in memory only.

    Instances of this class is used more or less like a context being passed around.
    None of this data is persisted anywhere.

    This is more or less an interface to the current 'pending_request' in the session,
    identified by the request_ref.
    """

    request_ref: RequestRef

    # SAML request, loaded lazily from the session using `key'
    _pending_request: Optional[IdP_PendingRequest] = field(default=None, init=False, repr=False)

    def __str__(self) -> str:
        return f'<{self.__class__.__name__}: key={self.request_ref}>'

    @property
    def pending_request(self) -> IdP_PendingRequest:
        if self._pending_request is None:
            from eduid.webapp.common.session import session

            pending_request = session.idp.pending_requests.get(self.request_ref)
            if not pending_request:
                raise RuntimeError(f'SAML data with ref {self.request_ref} not found in session')
            self._pending_request = pending_request

        return self._pending_request

    @property
    def request_id(self) -> Optional[str]:
        raise NotImplementedError('Subclass must implement request_id')

    @property
    def authn_contexts(self) -> List[str]:
        raise NotImplementedError('Subclass must implement authn_contexts')

    @property
    def reauthn_required(self) -> bool:
        raise NotImplementedError('Subclass must implement force_authn')


TLoginContextSubclass = TypeVar('TLoginContextSubclass', bound='LoginContext')


@dataclass
class LoginContextSAML(LoginContext):

    _saml_req: Optional['IdP_SAMLRequest'] = field(default=None, init=False, repr=False)

    @property
    def SAMLRequest(self) -> str:
        pending = self.pending_request
        if not isinstance(pending, IdP_SAMLPendingRequest):
            raise ValueError('Pending request not initialised (or not a SAML request)')
        if not isinstance(pending.request, str):
            raise ValueError('saml_data.request not initialised')
        return pending.request

    @property
    def RelayState(self) -> str:
        pending = self.pending_request
        if not isinstance(pending, IdP_SAMLPendingRequest):
            raise ValueError('Pending request not initialised (or not a SAML request)')
        return pending.relay_state or ''

    @property
    def binding(self) -> str:
        pending = self.pending_request
        if not isinstance(pending, IdP_SAMLPendingRequest):
            raise ValueError('Pending request not initialised (or not a SAML request)')
        if not isinstance(pending.binding, str):
            raise ValueError('saml_data.binding not initialised')
        return pending.binding

    @property
    def query_string(self) -> str:
        qs = {'SAMLRequest': self.SAMLRequest, 'RelayState': self.RelayState}
        return urlencode(qs)

    @property
    def saml_req(self) -> IdP_SAMLRequest:
        if self._saml_req is None:
            # avoid circular import
            from eduid.webapp.idp.app import current_idp_app as current_app

            self._saml_req = IdP_SAMLRequest(
                self.SAMLRequest, self.binding, current_app.IDP, debug=current_app.conf.debug
            )
        return self._saml_req

    @property
    def request_id(self) -> Optional[str]:
        return self.saml_req.request_id

    @property
    def authn_contexts(self) -> List[str]:
        return self.saml_req.get_requested_authn_contexts()

    @property
    def reauthn_required(self) -> bool:
        return self.saml_req.force_authn


@dataclass
class LoginContextOtherDevice(LoginContext):

    other_device_req: OtherDevice = field(default=None, repr=False)

    @property
    def request_id(self) -> Optional[str]:
        return self.other_device_req.request_id

    @property
    def authn_contexts(self) -> List[str]:
        if not self.other_device_req.authn_context:
            return []
        return [str(self.other_device_req.authn_context)]

    @property
    def reauthn_required(self) -> bool:
        return self.other_device_req.reauthn_required
