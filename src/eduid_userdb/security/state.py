# -*- coding: utf-8 -*-

from __future__ import absolute_import

import copy

import bson
from six import string_types

from eduid_userdb.deprecation import deprecated
from eduid_userdb.element import _set_something_ts
from eduid_userdb.exceptions import UserDBValueError, UserHasUnknownData
from eduid_userdb.security.element import CodeElement

__author__ = 'lundberg'


# @deprecated("Remove once the password reset views are served from their own webapp")
class PasswordResetState(object):
    @deprecated("Remove once the password reset views are served from their own webapp")
    def __init__(self, data, raise_on_unknown=True):

        self._data_in = copy.deepcopy(data)  # to not modify callers data
        self._data = dict()

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
        self._data['generated_password'] = self._data_in.pop('generated_password', None)

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
    def id(self):
        """
        Get state id

        :rtype: bson.ObjectId
        """
        return self._data['_id']

    @property
    def reference(self):
        """
        Audit reference to help cross reference audit log and events

        :rtype: six.string_types
        """
        return '{}'.format(self.id)

    @property
    def eppn(self):
        """
        Get the user's eppn

        :rtype: six.string_types
        """
        return self._data['eduPersonPrincipalName']

    # -----------------------------------------------------------------
    @property
    def method(self):
        """
        Get the password reset method

        :rtype: six.string_types
        """
        return self._data['method']

    @method.setter
    def method(self, value):
        """
        Set the password reset method

        :rtype: six.string_types
        """
        if value is None or isinstance(value, string_types):
            self._data['method'] = value

    # -----------------------------------------------------------------
    @property
    def created_ts(self):
        """
        :return: Timestamp of element creation.
        :rtype: datetime.datetime
        """
        return self._data.get('created_ts')

    @created_ts.setter
    def created_ts(self, value):
        """
        :param value: Timestamp of element creation.
                      Value None is ignored, True is short for datetime.utcnow().
        :type value: datetime.datetime | True | None
        """
        _set_something_ts(self._data, 'created_ts', value)

    # -----------------------------------------------------------------
    @property
    def modified_ts(self):
        """
        :return: Timestamp of last modification in the database.
                 None if User has never been written to the database.
        :rtype: datetime.datetime | None
        """
        return self._data.get('modified_ts')

    @modified_ts.setter
    def modified_ts(self, value):
        """
        :param value: Timestamp of modification.
                      Value None is ignored, True is short for datetime.utcnow().
        :type value: datetime.datetime | True | None
        """
        _set_something_ts(self._data, 'modified_ts', value, allow_update=True)

    @property
    def extra_security(self):
        """
        Get the extra security alternatives

        :rtype: dict
        """
        return self._data['extra_security']

    @extra_security.setter
    def extra_security(self, value):
        """
        :param value: dict of extra security alternatives
        :type value: dict
        """
        if value is None or isinstance(value, dict):
            self._data['extra_security'] = value

    @property
    def generated_password(self):
        """
        Get the generated password

        :rtype: string | None
        """
        return self._data['generated_password']

    @generated_password.setter
    def generated_password(self, value):
        """
        :param value: generated password
        :type value: string
        """
        if value is None or isinstance(value, string_types):
            self._data['generated_password'] = value

    def to_dict(self):
        res = copy.copy(self._data)  # avoid caller messing with our _data
        return res


# @deprecated("Remove once the password reset views are served from their own webapp")
class PasswordResetEmailState(PasswordResetState):
    @deprecated("Remove once the password reset views are served from their own webapp")
    def __init__(
        self, eppn=None, email_address=None, email_code=None, created_ts=None, data=None, raise_on_unknown=True
    ):
        if data is None:
            if created_ts is None:
                created_ts = True
            data = dict(
                eduPersonPrincipalName=eppn, email_address=email_address, email_code=email_code, created_ts=created_ts,
            )

        self._data_in = copy.deepcopy(data)  # to not modify callers data
        self._data = dict()

        # email_address
        email_address = self._data_in.pop('email_address')
        # email_code
        email_code = self._data_in.pop('email_code')

        PasswordResetState.__init__(self, self._data_in, raise_on_unknown)

        # things with setters
        self.method = 'email'
        self.email_address = email_address
        self.email_code = CodeElement.parse(application='security', code_or_element=email_code)

    @property
    def email_address(self):
        """
        This is the e-mail address.

        :return: E-mail address.
        :rtype: str
        """
        return self._data['email_address']

    @email_address.setter
    def email_address(self, value):
        """
        :param value: e-mail address.
        :type value: str | unicode
        """
        if not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'email_address': {!r}".format(value))
        self._data['email_address'] = str(value.lower())

    @property
    def email_code(self):
        """
        This is the code sent out with email

        :return: Code element
        :rtype: CodeElement
        """
        return self._data['email_code']

    @email_code.setter
    def email_code(self, value):
        """
        :param value: Code element
        :type value: CodeElement
        """
        if not isinstance(value, CodeElement):
            raise UserDBValueError("Invalid 'email_code': {!r}".format(value))
        self._data['email_code'] = value

    def to_dict(self):
        res = super(PasswordResetEmailState, self).to_dict()
        res['email_code'] = self.email_code.to_dict()
        return res


# @deprecated("Remove once the password reset views are served from their own webapp")
class PasswordResetEmailAndPhoneState(PasswordResetEmailState):
    @deprecated("Remove once the password reset views are served from their own webapp")
    def __init__(
        self,
        eppn=None,
        email_address=None,
        email_code=None,
        phone_number=None,
        phone_code=None,
        created_ts=None,
        data=None,
        raise_on_unknown=True,
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

        self._data_in = copy.deepcopy(data)  # to not modify callers data
        self._data = dict()

        # phone_number
        phone_number = self._data_in.pop('phone_number', None)
        # phone_code
        phone_code = self._data_in.pop('phone_code', None)

        PasswordResetEmailState.__init__(self, data=self._data_in, raise_on_unknown=raise_on_unknown)

        # things with setters
        self.method = 'email_and_phone'
        self.phone_number = phone_number
        self.phone_code = CodeElement.parse(application='security', code_or_element=phone_code)

    @classmethod
    def from_email_state(cls, email_state, phone_number, phone_code):
        data = email_state.to_dict()
        data['phone_number'] = phone_number
        data['phone_code'] = phone_code
        return cls(data=data)

    @property
    def phone_number(self):
        """
        :rtype: six.string_types
        """
        return self._data['phone_number']

    @phone_number.setter
    def phone_number(self, value):
        """
        :param value: phone number
        :rtype: six.string_types
        """
        if value is None:
            return
        if not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'phone_number': {!r}".format(value))
        self._data['phone_number'] = value

    @property
    def phone_code(self):
        """
        This is the code sent out with sms

        :return: Code element
        :rtype: CodeElement
        """
        return self._data['phone_code']

    @phone_code.setter
    def phone_code(self, value):
        """
        :param value: Code element
        :type value: CodeElement
        """
        if value is None:
            return
        if not isinstance(value, CodeElement):
            raise UserDBValueError("Invalid 'phone_code': {!r}".format(value))
        self._data['phone_code'] = value

    def to_dict(self):
        res = super(PasswordResetEmailAndPhoneState, self).to_dict()
        if self._data.get('phone_code'):
            res['phone_code'] = self.phone_code.to_dict()
        return res
