from __future__ import absolute_import

from bson import ObjectId

from eduid_userdb.element import ElementList, DuplicateElementViolation
from eduid_userdb.exceptions import UserHasUnknownData
from eduid_userdb.credentials import Credential, password_from_dict, u2f_from_dict


class CredentialList(ElementList):
    """
    Hold a list of authentication credential instances.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there no duplicates in the list.

    :param credentials: List of credentials
    :type credentials: [dict | Password | U2F]
    """

    def __init__(self, creds, raise_on_unknown=True):
        elements = []
        for this in creds:
            if isinstance(this, Credential):
                credential = this
            elif isinstance(this, dict) and 'salt' in this:
                credential = password_from_dict(this, raise_on_unknown)
            elif isinstance(this, dict) and 'keyhandle' in this:
                credential = u2f_from_dict(this, raise_on_unknown)
            else:
                raise UserHasUnknownData('Unknown credential data (type {}): {!r}'.format(type(this), this))
            elements.append(credential)

        ElementList.__init__(self, elements)

    def add(self, element):
        if self.find(element.key):
            raise DuplicateElementViolation("credential {!s} already in list".format(element.key))
        super(CredentialList, self).add(element)

    def find(self, key):
        if isinstance(key, ObjectId):
            # backwards compatible - Password.key (credential_id) changed from ObjectId to str
            key = str(key)
        return super(CredentialList, self).find(key)
