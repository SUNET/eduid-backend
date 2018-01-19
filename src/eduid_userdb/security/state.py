# -*- coding: utf-8 -*-

from __future__ import absolute_import

import bson
import copy
import datetime
from six import string_types

from eduid_userdb.element import _set_something_ts
from eduid_userdb.exceptions import UserHasUnknownData, UserDBValueError
from eduid_userdb.security.element import CodeElement

__author__ = 'lundberg'


class PasswordResetState(object):
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
        eppn = self._data_in.pop('eduPersonPrincipalName')
        self._data['eduPersonPrincipalName'] = eppn

        # method
        method = self._data_in.pop('method')
        self._data['method'] = method

        self.modified_ts = self._data_in.pop('modified_ts', None)

        if len(self._data_in) > 0:
            if raise_on_unknown:
                raise UserHasUnknownData('Unknown data: {!r}'.format(
                    self._data_in.keys()
                ))
            # Just keep everything that is left as-is
            self._data.update(self._data_in)

    def __repr__(self):
        return '<eduID {!s}: {!s}>'.format(self.__class__.__name__, self.eppn)

    @property
    def eppn(self):
        """
        Get the user's eppn

        :rtype: six.string_types
        """
        return self._data['eduPersonPrincipalName']

    @property
    def method(self):
        """
        Get the password reset method

        :rtype: six.string_types
        """
        return self._data['method']

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

    def to_dict(self):
        res = copy.copy(self._data)  # avoid caller messing with our _data
        return res


class PasswordResetEmailState(PasswordResetState):
    def __init__(self, application=None, eppn=None, email_address=None, email_code=None, created_ts=None, data=None,
                 raise_on_unknown=True):
        if data is None:
            if created_ts is None:
                created_ts = True
            data = dict(eppn=eppn,
                        email_address=email_address,
                        email_code=email_code,
                        created_by=application,
                        created_ts=created_ts,
                        )

        self._data_in = copy.deepcopy(data)  # to not modify callers data
        self._data = dict()

        # method
        self._data['method'] = 'email'
        # email_address
        email_address = self._data_in.pop('email_address')
        # email_code
        email_code = self._data_in.pop('email_code')

        PasswordResetState.__init__(self, self._data_in, raise_on_unknown)

        # things with setters
        self.email_address = email_address
        self.email_code = CodeElement(application=application, code=email_code)

    @property
    def email_address(self):
        """
        This is the e-mail address.

        :return: E-mail address.
        :rtype: str
        """
        return self._data['email']

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
        return self._data['email']

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


class PasswordResetEmailAndPhoneState(PasswordResetEmailState):
    def __init__(self, application=None, eppn=None, email_address=None, email_code=None, phone_number=None,
                 phone_code=None, created_ts=None, data=None, raise_on_unknown=True):
        if data is None:
            if created_ts is None:
                created_ts = True
            data = dict(eppn=eppn,
                        email_address=email_address,
                        email_code=email_code,
                        phone_number=phone_number,
                        phone_code=phone_code,
                        created_by=application,
                        created_ts=created_ts,
                        )

        self._data_in = copy.deepcopy(data)  # to not modify callers data
        self._data = dict()

        # method
        self._data['method'] = 'email_and_phone'
        # phone_number
        phone_number = self._data_in.pop('phone_number', None)
        # phone_code
        phone_code = self._data_in.pop('phone_code', None)

        PasswordResetEmailState.__init__(self, self._data_in, raise_on_unknown)

        # things with setters
        self.phone_number = phone_number
        self.phone_code = CodeElement(application=application, code=phone_code)

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
            res['phone_code'] = self.email_code.to_dict()
