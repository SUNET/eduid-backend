from bson import ObjectId

from eduid.userdb.credentials.base import Credential
from eduid.userdb.credentials.fido import U2F, Webauthn
from eduid.userdb.credentials.password import Password
from eduid.userdb.element import DuplicateElementViolation, ElementList
from eduid.userdb.exceptions import UserHasUnknownData


class CredentialList(ElementList):
    """
    Hold a list of authentication credential instances.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there no duplicates in the list.

    :param credentials: List of credentials
    :type credentials: [dict | Password | U2F]
    """

    def __init__(self, creds):
        elements = []
        for this in creds:
            if isinstance(this, Credential):
                credential = this
            elif isinstance(this, dict) and 'salt' in this:
                credential = Password.from_dict(this)
            elif isinstance(this, dict) and 'keyhandle' in this:
                if 'public_key' in this:
                    credential = U2F.from_dict(this)
                else:
                    credential = Webauthn.from_dict(this)
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
