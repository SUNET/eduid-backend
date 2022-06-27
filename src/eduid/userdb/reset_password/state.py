# -*- coding: utf-8 -*-
#
# Copyright (c) 2019 SUNET
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
#     3. Neither the name of the SUNET nor the names of its
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
from __future__ import annotations

import datetime
import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional, Type, TypeVar

import bson

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.reset_password.element import CodeElement

TResetPasswordStateSubclass = TypeVar('TResetPasswordStateSubclass', bound='ResetPasswordState')

logger = logging.getLogger(__name__)


@dataclass
class ResetPasswordState(object):
    """ """

    eppn: str
    id: bson.ObjectId = field(default_factory=lambda: bson.ObjectId())
    reference: str = field(init=False)
    method: Optional[str] = None
    created_ts: datetime.datetime = field(default_factory=utc_now)
    modified_ts: Optional[datetime.datetime] = None
    extra_security: Optional[Dict[str, Any]] = None
    generated_password: bool = False

    def __post_init__(self):
        self.reference = str(self.id)

    def __str__(self):
        return '<eduID {!s}: {!s}>'.format(self.__class__.__name__, self.eppn)

    def to_dict(self) -> dict:
        res = asdict(self)
        res['eduPersonPrincipalName'] = res.pop('eppn')
        res['_id'] = res.pop('id')
        return res

    @classmethod
    def from_dict(cls: Type[TResetPasswordStateSubclass], data: Dict[str, Any]) -> TResetPasswordStateSubclass:
        data['eppn'] = data.pop('eduPersonPrincipalName')
        data['id'] = data.pop('_id')
        if 'reference' in data:
            data.pop('reference')
        return cls(**data)

    def throttle_time_left(self, min_wait: datetime.timedelta) -> datetime.timedelta:
        if self.modified_ts is None or min_wait.total_seconds() == 0:
            return datetime.timedelta()
        throttle_ends = self.modified_ts + min_wait
        return throttle_ends - utc_now()

    def is_throttled(self, min_wait: datetime.timedelta) -> bool:
        time_left = self.throttle_time_left(min_wait)
        if int(time_left.total_seconds()) > 0:
            logger.warning(f'Resend throttled for {time_left}')
            return True
        return False


@dataclass
class _ResetPasswordEmailStateRequired:
    """ """

    email_address: str
    email_code: CodeElement


@dataclass
class ResetPasswordEmailState(ResetPasswordState, _ResetPasswordEmailStateRequired):
    """ """

    def __post_init__(self):
        super().__post_init__()
        self.method = 'email'
        self.email_code = CodeElement.parse(application='security', code_or_element=self.email_code)

    def to_dict(self):
        res = super().to_dict()
        res['email_code'] = self.email_code.to_dict()
        return res


@dataclass
class _ResetPasswordEmailAndPhoneStateRequired:
    """ """

    phone_number: str
    phone_code: CodeElement


@dataclass
class ResetPasswordEmailAndPhoneState(ResetPasswordEmailState, _ResetPasswordEmailAndPhoneStateRequired):
    """ """

    def __post_init__(self):
        super().__post_init__()
        self.method = 'email_and_phone'
        self.phone_code = CodeElement.parse(application='security', code_or_element=self.phone_code)

    @classmethod
    def from_email_state(
        cls: Type[ResetPasswordEmailAndPhoneState],
        email_state: ResetPasswordEmailState,
        phone_number: str,
        phone_code: str,
    ) -> ResetPasswordEmailAndPhoneState:
        data = email_state.to_dict()
        data['phone_number'] = phone_number
        data['phone_code'] = phone_code
        return cls.from_dict(data=data)

    def to_dict(self) -> dict:
        res = super().to_dict()
        res['phone_code'] = self.phone_code.to_dict()
        return res
