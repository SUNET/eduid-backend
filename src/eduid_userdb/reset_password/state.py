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
import copy
import datetime
from typing import Dict, Mapping, Optional, Union, cast

import bson

from eduid_userdb.element import _set_something_ts
from eduid_userdb.exceptions import UserDBValueError, UserHasUnknownData
from eduid_userdb.reset_password.element import CodeElement


class ResetPasswordState(object):
    def __init__(self, data: dict, raise_on_unknown: bool = True):

        self._data_in = copy.deepcopy(data)  # to not modify callers data
        self._data: Dict = dict()

        # things without setters
        # _id
        _id = self._data_in.pop('_id', None)
        if _id is None:
            _id = bson.ObjectId()
        if not isinstance(_id, bson.ObjectId):
            _id = bson.ObjectId(_id)
        self._data['_id'] = _id
        # eppn
        self._data['eduPersonPrincipalName'] = self._data_in.pop('eduPersonPrincipalName')

        # method
        self._data['method'] = self._data_in.pop('method', None)

        # extra security alternatives
        self._data['extra_security'] = self._data_in.pop('extra_security', None)

        # generated password
        self._data['generated_password'] = self._data_in.pop('generated_password', False)

        # meta
        self.created_ts = self._data_in.pop('created_ts', None)
        self.modified_ts = self._data_in.pop('modified_ts', None)

        if len(self._data_in) > 0:
            if raise_on_unknown:
                raise UserHasUnknownData('Unknown data: {!r}'.format(self._data_in.keys()))
            # Just keep everything that is left as-is
            self._data.update(self._data_in)

    def __repr__(self):
        return '<eduID {!s}: {!s}>'.format(self.__class__.__name__, self.eppn)

    @property
    def id(self) -> bson.ObjectId:
        """
        Get state id
        """
        return self._data['_id']

    @property
    def reference(self) -> str:
        """
        Audit reference to help cross reference audit log and events
        """
        return f'{self.id}'

    @property
    def eppn(self) -> str:
        """
        Get the user's eppn
        """
        return self._data['eduPersonPrincipalName']

    # -----------------------------------------------------------------
    @property
    def method(self) -> str:
        """
        Get the password reset method
        """
        return self._data['method']

    @method.setter
    def method(self, value: str):
        """
        Set the password reset method
        """
        if value is None or isinstance(value, str):
            self._data['method'] = value

    # -----------------------------------------------------------------
    @property
    def created_ts(self) -> datetime.datetime:
        """
        :return: Timestamp of element creation.
        """
        return cast(datetime.datetime, self._data.get('created_ts'))

    @created_ts.setter
    def created_ts(self, value: Optional[Union[datetime.datetime, bool]]):
        """
        :param value: Timestamp of element creation.
                      Value None is ignored, True is short for datetime.utcnow().
        """
        _set_something_ts(self._data, 'created_ts', value)

    # -----------------------------------------------------------------
    @property
    def modified_ts(self) -> Optional[Union[datetime.datetime, bool]]:
        """
        :return: Timestamp of last modification in the database.
                 None if User has never been written to the database.
        """
        return self._data.get('modified_ts')

    @modified_ts.setter
    def modified_ts(self, value: Optional[Union[datetime.datetime, bool]]):
        """
        :param value: Timestamp of modification.
                      Value None is ignored, True is short for datetime.utcnow().
        """
        _set_something_ts(self._data, 'modified_ts', value, allow_update=True)

    @property
    def extra_security(self) -> dict:
        """
        Get the extra security alternatives
        """
        return self._data['extra_security']

    @extra_security.setter
    def extra_security(self, value: dict):
        """
        :param value: dict of extra security alternatives
        """
        if value is None or isinstance(value, dict):
            self._data['extra_security'] = value

    @property
    def generated_password(self) -> Optional[bool]:
        """
        Get whether the password was generated
        """
        return self._data['generated_password']

    @generated_password.setter
    def generated_password(self, value: bool):
        """
        :param value: is generated password
        """
        if value is None or isinstance(value, bool):
            self._data['generated_password'] = value

    def to_dict(self) -> dict:
        res = copy.copy(self._data)  # avoid caller messing with our _data
        return res


class ResetPasswordEmailState(ResetPasswordState):
    def __init__(
        self,
        eppn: Optional[str] = None,
        email_address: Optional[str] = None,
        email_code: Optional[Union[str, CodeElement]] = None,
        created_ts: Optional[Union[bool, datetime.datetime]] = None,
        data: Optional[Mapping] = None,
        raise_on_unknown: bool = True,
    ):
        if data is None:
            if created_ts is None:
                created_ts = True
            if email_address is None:
                raise ValueError('Neither email_address nor data provided')
            if email_code is None:
                raise ValueError('Neither email_code nor data provided')
            data = dict(
                eduPersonPrincipalName=eppn, email_address=email_address, email_code=email_code, created_ts=created_ts,
            )

        self._data_in = copy.deepcopy(cast(dict, data))  # to not modify callers data
        self._data = dict()

        email_address = self._data_in.pop('email_address')
        email_code = self._data_in.pop('email_code')

        ResetPasswordState.__init__(self, self._data_in, raise_on_unknown)

        # things with setters
        self.method = 'email'
        self.email_address = email_address
        self.email_code = CodeElement.parse(application='security', code_or_element=email_code)

    @property
    def email_address(self) -> str:
        """
        This is the e-mail address.
        """
        return self._data['email_address']

    @email_address.setter
    def email_address(self, value: str):
        """
        :param value: e-mail address.
        """
        if not isinstance(value, str):
            raise UserDBValueError(f"Invalid 'email_address': {value}")
        self._data['email_address'] = str(value.lower())

    @property
    def email_code(self) -> CodeElement:
        """
        This is the code sent out with email
        """
        return self._data['email_code']

    @email_code.setter
    def email_code(self, value: CodeElement):
        """
        :param value: Code element
        """
        if not isinstance(value, CodeElement):
            raise UserDBValueError(f"Invalid 'email_code': {value}")
        self._data['email_code'] = value

    def to_dict(self):
        res = super(ResetPasswordEmailState, self).to_dict()
        res['email_code'] = self.email_code.to_dict()
        return res


class ResetPasswordEmailAndPhoneState(ResetPasswordEmailState):
    def __init__(
        self,
        eppn: Optional[str] = None,
        email_address: Optional[str] = None,
        email_code: Optional[str] = None,
        phone_number: Optional[str] = None,
        phone_code: Optional[str] = None,
        created_ts: Optional[Union[datetime.datetime, bool]] = None,
        data: Optional[Mapping] = None,
        raise_on_unknown: bool = True,
    ):
        if data is None:
            if created_ts is None:
                created_ts = True
            data = dict(
                eduPersonPrincipalName=eppn,
                email_address=email_address,
                email_code=email_code,
                phone_number=phone_number,
                phone_code=phone_code,
                created_ts=created_ts,
            )

        self._data_in = copy.deepcopy(cast(dict, data))  # to not modify callers data
        self._data = dict()

        # phone_number
        phone_number = cast(str, self._data_in.pop('phone_number'))
        # phone_code
        phone_code = cast(str, self._data_in.pop('phone_code'))

        ResetPasswordEmailState.__init__(self, data=self._data_in, raise_on_unknown=raise_on_unknown)

        # things with setters
        self.method = 'email_and_phone'
        self.phone_number = phone_number
        self.phone_code = CodeElement.parse(application='security', code_or_element=phone_code)

    @classmethod
    def from_email_state(
        cls, email_state: ResetPasswordEmailState, phone_number: str, phone_code: str
    ) -> ResetPasswordState:
        data = email_state.to_dict()
        data['phone_number'] = phone_number
        data['phone_code'] = phone_code
        return cls(data=data)

    @property
    def phone_number(self) -> str:
        """
        The phone number
        """
        return self._data['phone_number']

    @phone_number.setter
    def phone_number(self, value: str):
        """
        :param value: phone number
        """
        if value is None:
            return
        if not isinstance(value, str):
            raise UserDBValueError(f"Invalid 'phone_number': {value}")
        self._data['phone_number'] = value

    @property
    def phone_code(self) -> CodeElement:
        """
        This is the code sent out with sms
        """
        return self._data['phone_code']

    @phone_code.setter
    def phone_code(self, value: CodeElement):
        """
        :param value: Code element
        """
        if value is None:
            return
        if not isinstance(value, CodeElement):
            raise UserDBValueError("Invalid 'phone_code': {!r}".format(value))
        self._data['phone_code'] = value

    def to_dict(self) -> dict:
        res = super(ResetPasswordEmailAndPhoneState, self).to_dict()
        if self._data.get('phone_code'):
            res['phone_code'] = self.phone_code.to_dict()
        return res
