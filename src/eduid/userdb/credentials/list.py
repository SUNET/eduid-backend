from __future__ import annotations

from typing import Any, Dict, List, Type

from bson import ObjectId
from pydantic import Field

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
    """

    elements: List[Credential] = Field(default_factory=list)

    def _get_elements(self) -> List[Credential]:
        """
        This construct allows typing to infer the correct type of the elements
        when called from functions in the superclass.
        """
        return self.elements

    @classmethod
    def from_list_of_dicts(cls: Type[CredentialList], items: List[Dict[str, Any]]) -> CredentialList:
        elements = []
        for this in items:
            credential: Credential
            if isinstance(this, dict) and 'salt' in this:
                credential = Password.from_dict(this)
            elif isinstance(this, dict) and 'keyhandle' in this:
                if 'public_key' in this:
                    credential = U2F.from_dict(this)
                else:
                    credential = Webauthn.from_dict(this)
            else:
                raise UserHasUnknownData('Unknown credential data (type {}): {!r}'.format(type(this), this))
            elements.append(credential)

        return cls(elements=elements)

    def add(self, element):
        if self.find(element.key):
            raise DuplicateElementViolation("credential {!s} already in list".format(element.key))
        super(CredentialList, self).add(element)

    def find(self, key):
        if isinstance(key, ObjectId):
            # backwards compatible - Password.key (credential_id) changed from ObjectId to str
            key = str(key)
        return super(CredentialList, self).find(key)
