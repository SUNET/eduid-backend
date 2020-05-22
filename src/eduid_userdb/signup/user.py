#
# Copyright (c) 2015 NORDUnet A/S
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

__author__ = 'ft'

import copy

import bson
import six
from typing import Optional, Union

from eduid_userdb import User
from eduid_userdb.exceptions import UserIsRevoked
from eduid_userdb.proofing import EmailProofingElement


class SignupUser(User):
    """
    Subclass of eduid_userdb.User with eduid Signup application specific data.
    """

    def __init__(self, userid=None, eppn=None, subject='physical person', data=None,
                 raise_on_unknown=False, called_directly=True):
        data_in = data
        data = copy.copy(data_in)  # to not modify callers data

        if data is None:
            if userid is None:
                userid = bson.ObjectId()
            data = dict(_id=userid, eduPersonPrincipalName=eppn, subject=subject,)
        _social_network = data.pop('social_network', None)
        _social_network_id = data.pop('social_network_id', None)
        _pending_mail_address = data.pop('pending_mail_address', None)
        _proofing_reference = data.pop('proofing_reference', None)
        if _pending_mail_address:
            _pending_mail_address = EmailProofingElement(data=_pending_mail_address)
        self._pending_mail_address = None

        User.__init__(self, data=data, raise_on_unknown=raise_on_unknown, called_directly=called_directly)

        # now self._data exists so we can call our setters
        self.social_network = _social_network
        self.social_network_id = _social_network_id
        self.pending_mail_address = _pending_mail_address
        if _proofing_reference:
            self.proofing_reference = _proofing_reference

    @classmethod
    def construct_user(
        cls,
        userid: Optional[Union[bson.ObjectId, str]] = None,
        eppn: Optional[str] = None,
        pending_mail_address: Optional[EmailProofingElement] = None,
        proofing_reference: Optional[str] = None,
        **kwargs
    ) -> User:
        """
        """
        if userid is not None:
            kwargs['_id'] = userid
        if eppn is not None:
            kwargs['eduPersonPrincipalName'] = eppn
        user = cls.from_dict(kwargs)

        if pending_mail_address is not None:
            user.pending_mail_address = pending_mail_address

        if proofing_reference is not None:
            user.proofing_reference = proofing_reference

        return user

    def _parse_check_invalid_users(self):
        """
        Part of User.__init__().

        Check users that can't be loaded for some known reason.
        """
        if 'revoked_ts' in self._data_in:
            raise UserIsRevoked(
                'User {!s}/{!s} was revoked at {!s}'.format(
                    self._data_in.get('_id'), self._data_in.get('eduPersonPrincipalName'), self._data_in['revoked_ts']
                )
            )

    def to_dict(self, old_userdb_format=False):
        res = User.to_dict(self, old_userdb_format=old_userdb_format)
        if self._pending_mail_address is not None:
            res['pending_mail_address'] = self._pending_mail_address.to_dict()
        return res

    # -----------------------------------------------------------------
    @property
    def social_network(self):
        """
        Get the user's social_network.

        :rtype: str
        """
        return self._data.get('social_network', '')

    @social_network.setter
    def social_network(self, value):
        """
        :param value: Set the name of the social_network used to do SNA signup.
        :type value: str | unicode
        """
        if value is not None:
            self._data['social_network'] = value

    # -----------------------------------------------------------------
    @property
    def social_network_id(self):
        """
        Get the user's social network id.

        :rtype: str
        """
        return self._data.get('social_network_id', '')

    @social_network_id.setter
    def social_network_id(self, value):
        """
        :param value: Set the user's social network id.
        :type value: str | unicode
        """
        if value is not None:
            self._data['social_network_id'] = value

    # -----------------------------------------------------------------
    @property
    def pending_mail_address(self):
        """
        Get the user's pending (unconfirmed) mail address.

        In the userdb, the mail_addresses attribute requires a primary e-mail address,
        and it has to be verified already. Signup is really the special case, so
        we have a special attribute for it.

        :rtype: eduid_userdb.proofing.EmailProofingElement | None
        """
        return self._pending_mail_address

    @pending_mail_address.setter
    def pending_mail_address(self, value):
        """
        :param value: Set the user's pending (unconfirmed) mail address.
        :type value: eduid_userdb.proofing.EmailProofingElement | None
        """
        if value is not None and not isinstance(value, EmailProofingElement):
            raise ValueError('Must be eduid_userdb.proofing.EmailProofingElement')
        self._pending_mail_address = value

    @property
    def proofing_reference(self):
        """
        Holds a reference id that is used for connecting msg tasks with proofing log statements.

        :return: reference id
        :rtype: six.string_types
        """
        if not self._data.get('proofing_reference', None):
            ref = str(bson.objectid.ObjectId())
            self.proofing_reference = ref
        return self._data['proofing_reference']

    @proofing_reference.setter
    def proofing_reference(self, value):
        if not isinstance(value, six.string_types):
            raise ValueError('Must be type string')
        self._data['proofing_reference'] = value
