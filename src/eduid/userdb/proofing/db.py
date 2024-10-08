import logging
from abc import ABC
from collections.abc import Mapping
from operator import itemgetter
from typing import Any, Generic, TypeVar

from eduid.userdb.db import BaseDB, SaveResult, TUserDbDocument
from eduid.userdb.proofing.state import (
    EmailProofingState,
    LetterProofingState,
    OidcProofingState,
    OrcidProofingState,
    PhoneProofingState,
    ProofingState,
)
from eduid.userdb.proofing.user import ProofingUser
from eduid.userdb.userdb import UserDB, UserSaveResult

logger = logging.getLogger(__name__)

__author__ = "lundberg"

ProofingStateInstance = TypeVar("ProofingStateInstance", bound=ProofingState)

ProofingStateVar = TypeVar("ProofingStateVar")


class ProofingStateDB(BaseDB, Generic[ProofingStateVar], ABC):
    def __init__(self, db_uri: str, db_name: str, collection: str = "proofing_data") -> None:
        super().__init__(db_uri, db_name, collection)

    @classmethod
    def state_from_dict(cls, data: Mapping[str, Any]) -> ProofingStateVar:
        # must be implemented by subclass to get correct type information
        raise NotImplementedError()

    def get_state_by_eppn(self, eppn: str) -> ProofingStateVar | None:
        """
        Locate a state in the db given the state user's eppn.

        :param eppn: eduPersonPrincipalName

        :return: ProofingStateClass instance | None

        :raise self.DocumentDoesNotExist: No user match the search criteria
        :raise self.MultipleDocumentsReturned: More than one user matches the search criteria
        """

        data = self._get_document_by_attr("eduPersonPrincipalName", eppn)
        if not data:
            return None
        return self.state_from_dict(data)

    def get_latest_state_by_spec(self, spec: Mapping[str, Any]) -> ProofingStateVar | None:
        """
        Returns the latest inserted state and __removes any other state found__ defined by the spec .

        :param spec: the search filter
        :return: Latest state found
        """
        docs = self._get_documents_by_filter(spec)
        if not docs:
            return None

        if len(docs) > 1:
            # Ex. multiple states for same user and email address matched
            # This should not be possible but we have seen it happen
            states = sorted(docs, key=itemgetter("modified_ts"))
            state_to_keep = states.pop(-1)  # Keep latest state
            for state in states:
                self.remove_document(state["_id"])
            return self.state_from_dict(state_to_keep)

        return self.state_from_dict(docs[0])

    def save(self, state: ProofingStateVar, is_in_database: bool = True) -> SaveResult:
        """
        :param check_sync: Ensure the document hasn't been updated in the database since it was loaded
        """
        if not isinstance(state, ProofingState):
            raise TypeError("State must be a ProofingState subclass")
        spec: dict[str, Any] = {"eduPersonPrincipalName": state.eppn}

        result = self._save(state.to_dict(), spec, is_in_database=is_in_database)
        state.modified_ts = result.ts

        return result

    def remove_state(self, state: ProofingStateVar) -> None:
        """
        :param state: ProofingStateClass object
        """
        if not isinstance(state, ProofingState):
            raise TypeError("State must be a ProofingState subclass")

        self.remove_document({"eduPersonPrincipalName": state.eppn})


class LetterProofingStateDB(ProofingStateDB[LetterProofingState]):
    def __init__(self, db_uri: str, db_name: str = "eduid_idproofing_letter") -> None:
        super().__init__(db_uri, db_name)

    @classmethod
    def state_from_dict(cls, data: Mapping[str, Any]) -> LetterProofingState:
        return LetterProofingState.from_dict(data)


class EmailProofingStateDB(ProofingStateDB[EmailProofingState]):
    def __init__(self, db_uri: str, db_name: str = "eduid_email") -> None:
        super().__init__(db_uri, db_name)

    @classmethod
    def state_from_dict(cls, data: Mapping[str, Any]) -> EmailProofingState:
        return EmailProofingState.from_dict(data)

    def get_state_by_eppn_and_email(self, eppn: str, email: str) -> EmailProofingState | None:
        """
        Locate a state in the db given the eppn of the user and the
        email to be verified.

        :raise self.MultipleDocumentsReturned: More than one user matches the search criteria
        """
        spec = {"eduPersonPrincipalName": eppn, "verification.email": email}
        return self.get_latest_state_by_spec(spec)

    def remove_state(self, state: ProofingStateVar) -> None:
        """
        :param state: ProofingStateClass object

        :type state: ProofingStateClass
        """
        if not isinstance(state, EmailProofingState):
            raise TypeError("State must be a ProofingState subclass")

        self.remove_document({"eduPersonPrincipalName": state.eppn, "verification.email": state.verification.email})


class PhoneProofingStateDB(ProofingStateDB[PhoneProofingState]):
    def __init__(self, db_uri: str, db_name: str = "eduid_phone") -> None:
        super().__init__(db_uri, db_name)

    @classmethod
    def state_from_dict(cls, data: Mapping[str, Any]) -> PhoneProofingState:
        return PhoneProofingState.from_dict(data)

    def get_state_by_eppn_and_mobile(self, eppn: str, number: str) -> PhoneProofingState | None:
        """
        Locate a state in the db given the eppn of the user and the
        mobile to be verified.

        :param number: mobile to verify

        :return: ProofingStateClass instance | None

        :raise self.MultipleDocumentsReturned: More than one user
                                               matches the search criteria
        """
        spec = {"eduPersonPrincipalName": eppn, "verification.number": number}
        return self.get_latest_state_by_spec(spec)

    def remove_state(self, state: ProofingStateVar) -> None:
        """
        :param state: ProofingStateClass object

        :type state: ProofingStateClass
        """
        if not isinstance(state, PhoneProofingState):
            raise TypeError("State must be a ProofingState subclass")

        self.remove_document({"eduPersonPrincipalName": state.eppn, "verification.number": state.verification.number})


class OidcStateDB(ProofingStateDB[ProofingStateVar], Generic[ProofingStateVar], ABC):
    def get_state_by_oidc_state(self, oidc_state: str) -> ProofingStateVar | None:
        """
        Locate a state in the db given the user's OIDC state.

        :param oidc_state: OIDC state param

        :return: ProofingStateClass instance | None

        :raise self.MultipleDocumentsReturned: More than one user matches the search criteria
        """

        state = self._get_document_by_attr("state", oidc_state)
        if not state:
            return None
        return self.state_from_dict(state)


class OidcProofingStateDB(OidcStateDB[OidcProofingState]):
    def __init__(self, db_uri: str, db_name: str = "eduid_oidc_proofing") -> None:
        super().__init__(db_uri, db_name)

    @classmethod
    def state_from_dict(cls, data: Mapping[str, Any]) -> OidcProofingState:
        return OidcProofingState.from_dict(data)


class OrcidProofingStateDB(OidcStateDB[OrcidProofingState]):
    ProofingStateClass = OrcidProofingState

    def __init__(self, db_uri: str, db_name: str = "eduid_orcid") -> None:
        super().__init__(db_uri, db_name)

    @classmethod
    def state_from_dict(cls, data: Mapping[str, Any]) -> OrcidProofingState:
        return OrcidProofingState.from_dict(data)


class ProofingUserDB(UserDB[ProofingUser]):
    def __init__(self, db_uri: str, db_name: str, collection: str = "profiles") -> None:
        super().__init__(db_uri, db_name, collection=collection)

    def save(self, user: ProofingUser) -> UserSaveResult:
        return super().save(user)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> ProofingUser:
        return ProofingUser.from_dict(data)


class LetterProofingUserDB(ProofingUserDB):
    def __init__(self, db_uri: str, db_name: str = "eduid_idproofing_letter") -> None:
        super().__init__(db_uri, db_name)


class OidcProofingUserDB(ProofingUserDB):
    def __init__(self, db_uri: str, db_name: str = "eduid_oidc_proofing") -> None:
        super().__init__(db_uri, db_name)


class PhoneProofingUserDB(ProofingUserDB):
    def __init__(self, db_uri: str, db_name: str = "eduid_phone") -> None:
        super().__init__(db_uri, db_name)


class EmailProofingUserDB(ProofingUserDB):
    def __init__(self, db_uri: str, db_name: str = "eduid_email") -> None:
        super().__init__(db_uri, db_name)


class LookupMobileProofingUserDB(ProofingUserDB):
    def __init__(self, db_uri: str, db_name: str = "eduid_lookup_mobile_proofing") -> None:
        super().__init__(db_uri, db_name)


class OrcidProofingUserDB(ProofingUserDB):
    def __init__(self, db_uri: str, db_name: str = "eduid_orcid") -> None:
        super().__init__(db_uri, db_name)


class EidasProofingUserDB(ProofingUserDB):
    def __init__(self, db_uri: str, db_name: str = "eduid_eidas") -> None:
        super().__init__(db_uri, db_name)


class LadokProofingUserDB(ProofingUserDB):
    def __init__(self, db_uri: str, db_name: str = "eduid_ladok") -> None:
        super().__init__(db_uri, db_name)


class SvideIDProofingUserDB(ProofingUserDB):
    def __init__(self, db_uri: str, db_name: str = "eduid_svipe_id") -> None:
        super().__init__(db_uri, db_name)


class BankIDProofingUserDB(ProofingUserDB):
    def __init__(self, db_uri: str, db_name: str = "eduid_bankid") -> None:
        super().__init__(db_uri, db_name)


class FrejaEIDProofingUserDB(ProofingUserDB):
    def __init__(self, db_uri: str, db_name: str = "eduid_freja_eid") -> None:
        super().__init__(db_uri, db_name)
