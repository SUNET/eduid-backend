#
# Copyright (c) 2014-2015 NORDUnet A/S
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
# Author : Fredrik Thulin <fredrik@thulin.net>
#

from eduid_userdb.exceptions import EduIDUserDBError, UserDBValueError

from eduid_userdb.mail import MailAddressList

from eduid_userdb.exceptions import UserHasUnknownData


class User(object):
    """
    Generic eduID user object.

    :param mongo_doc: MongoDB document representing a user
    :type  mongo_doc: dict
    """

    def __init__(self, mongo_doc, raise_on_unknown = False):
        self._data = dict()
        # things without setters
        self._data['_id'] = mongo_doc.pop('_id')
        self._mail_addresses = MailAddressList(mongo_doc.pop('mailAliases', []))

        if len(mongo_doc) > 0:
            if raise_on_unknown:
                raise UserHasUnknownData('User {!s}/{!s} unknown data: {!r}'.format(
                    self.user_id, self.eppn, mongo_doc.keys()
                ))
            # Just keep everything that is left as-is
            self._data.update(mongo_doc)

    def __repr__(self):
        return '<eduID User: {!s}/{!s}>'.format(self.eppn, self.user_id)

    @property
    def user_id(self):
        """
        Get the user's oid in MongoDB.

        :rtype: bson.ObjectId
        """
        return self._data['_id']

    @property
    def eppn(self):
        """
        Get the user's eduPersonPrincipalName.

        :rtype: str
        """
        return self._data.get('eduPersonPrincipalName', '')

    @eppn.setter
    def eppn(self, eppn):
        """
        :param eppn: Set the user's eduPersonPrincipalName.
        :type eppn: str | unicode
        """
        if self._data.get('eduPersonPrincipalName') is not None:
            raise UserDBValueError('Overwriting an existing eduPersonPrincipalName is not allowed')
        self._data['eduPersonPrincipalName'] = eppn

    @property
    def given_name(self):
        """
        Get the user's givenName.

        :rtype: str | unicode
        """
        return self._data.get('givenName', '')

    @given_name.setter
    def given_name(self, name):
        """
        Set the user's givenName.

        :param name: the givenName to set
        :type  name: str | unicode
        """
        self._data['givenName'] = name

    @property
    def display_name(self):
        """
        Get the user's displayName.

        :rtype: str | unicode
        """
        return self._data.get('displayName', '')

    @display_name.setter
    def display_name(self, name):
        """
        Set the user's displayName.

        :param name: the displayName to set
        :type  name: str
        """
        self._data['displayName'] = name

    @property
    def sn(self):
        """
        Get the user's sn (family name).

        :rtype: str | unicode
        """
        return self._data.get('sn', '')

    @sn.setter
    def sn(self, sn):
        """
        Set the user's sn (family name).

        :param sn: the sn to set
        :type  sn: str
        """
        self._data['sn'] = sn

    @property
    def mail_addresses(self):
        """
        Get the user's email addresses.
        :return: MailAddressList object
        :rtype: MailAddressList
        """
        return self._mail_addresses.to_list()

    @mail_addresses.setter
    def mail_addresses(self, emails):
        """
        Set the user's email addresses,
        given as a list of dictionaries with the form:
            {
            'email': 'johnsmith@example.com',
            'verified': False,
            }
        This removes any previous list of email addresses
        that the user might have had.

        :param emails: the email addresses to set
        :type  emails: list
        """
        self._data['mailAliases'] = emails

    def add_verified_email(self, verified_email):
        """
        Pick one email address from the user's list
        and set it as verified.

        :param verified_email: the verified address
        :type verified_email: str
        """
        emails = self._data['mailAliases']
        for email in emails:
            if email['email'] == verified_email:
                email['verified'] = True

