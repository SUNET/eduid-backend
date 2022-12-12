# -*- coding: utf-8 -*-

from typing import Any, Dict, List, Mapping, Type, Union

from bson import ObjectId

from eduid.userdb.proofing import LetterProofingState
from eduid.userdb.signup import SignupUserDB
from eduid.userdb.support import models
from eduid.userdb.support.models import GenericFilterDict
from eduid.userdb.support.user import SupportUser
from eduid.userdb.userdb import BaseDB, UserDB

__author__ = "lundberg"

"""
Database classes for use in support applications to filter user data returned to support personnel. This
way we can minimize the risk of accidentally sharing any secret user data.
"""


class SupportUserDB(UserDB[SupportUser]):
    def __init__(self, db_uri: str, db_name: str = "eduid_am", collection: str = "attributes"):
        super().__init__(db_uri, db_name, collection=collection)

    @classmethod
    def user_from_dict(cls, data: Mapping[str, Any]) -> SupportUser:
        return SupportUser.from_dict(data)

    def search_users(self, query: str) -> List[SupportUser]:
        """
        :param query: search query, can be a user eppn, nin, mail address or phone number
        :return: A list of user docs
        """
        results = list()
        # We could do this with a custom filter (and one db call) but it is better to lean on existing methods
        # if the way we find users change in the future
        results.append(self.get_user_by_eppn(query))
        results.append(self.get_user_by_nin(query))
        results.extend(self.get_users_by_mail(query))
        results.extend(self.get_users_by_phone(query))
        users = [user for user in results if user]
        return users


class SupportSignupUserDB(SignupUserDB):

    pass


class SupportAuthnInfoDB(BaseDB):

    model = models.UserAuthnInfo

    def __init__(self, db_uri: str):
        db_name = "eduid_idp_authninfo"
        collection = "authn_info"
        super().__init__(db_uri, db_name, collection)

    def get_authn_info(self, user_id: Union[str, ObjectId]) -> Dict[str, Any]:
        """
        :param user_id: User objects user_id property
        :type user_id: ObjectId | str | unicode
        :return: A document dict
        :rtype: dict
        """
        if not isinstance(user_id, ObjectId):
            user_id = ObjectId(user_id)
        docs = self._get_documents_by_filter({"_id": user_id})
        if not docs:
            return dict()
        return self.model(dict(docs[0]))  # Cast to dict to allow mutability

    def get_credential_info(self, credential_id: str) -> Dict[str, Any]:
        """
        :param credential_id: Credential id
        :return: A document dict
        """
        doc = self._get_document_by_attr("_id", credential_id)
        if not doc:
            return dict()
        return self.model(dict(doc))  # Cast to dict to allow mutability


class SupportProofingDB(BaseDB):

    model: Type[GenericFilterDict] = GenericFilterDict

    def __init__(self, db_uri: str, db_name: str, collection: str):
        super().__init__(db_uri, db_name, collection)

    def get_proofing_state(self, eppn: str) -> Dict[str, Any]:
        """
        :param eppn: User objects eduPersonPrincipalName property
        :return: A document dict
        """
        doc = self._get_document_by_attr("eduPersonPrincipalName", eppn)
        if not doc:
            return dict()
        return self.model(dict(doc))  # Cast to dict to allow mutability

    def get_proofing_states(self, eppn: str) -> List[Dict[str, Any]]:
        """
        :param eppn: User objects eduPersonPrincipalName property
        :return: A list of document dicts
        """
        docs = self._get_documents_by_attr("eduPersonPrincipalName", eppn)
        return [self.model(dict(doc)) for doc in docs]  # Cast to dict to allow mutability


class SupportLetterProofingDB(SupportProofingDB):

    model = models.UserLetterProofing

    def __init__(self, db_uri: str):
        db_name = "eduid_idproofing_letter"
        collection = "proofing_data"
        super().__init__(db_uri, db_name, collection)

    def get_proofing_state(self, eppn: str) -> Dict[str, Any]:
        """
        :param eppn: User objects eduPersonPrincipalName property
        :return: A document dict
        """
        doc = self._get_document_by_attr("eduPersonPrincipalName", eppn)
        if not doc:
            return dict()
        # hack to support old official address format
        return self.model(dict(LetterProofingState.from_dict(doc).to_dict()))  # Cast to dict to allow mutability


class SupportOidcProofingDB(SupportProofingDB):

    model = models.UserOidcProofing

    def __init__(self, db_uri: str):
        db_name = "eduid_oidc_proofing"
        collection = "proofing_data"
        super().__init__(db_uri, db_name, collection)


class SupportEmailProofingDB(SupportProofingDB):

    model = models.UserEmailProofing

    def __init__(self, db_uri: str):
        db_name = "eduid_email"
        collection = "proofing_data"
        super().__init__(db_uri, db_name, collection)


class SupportPhoneProofingDB(SupportProofingDB):

    model = models.UserPhoneProofing

    def __init__(self, db_uri: str):
        db_name = "eduid_phone"
        collection = "proofing_data"
        super().__init__(db_uri, db_name, collection)


class SupportProofingLogDB(BaseDB):

    model = models.ProofingLogEntry

    def __init__(self, db_uri: str):
        db_name = "eduid_logs"
        collection = "proofing_log"
        super().__init__(db_uri, db_name, collection)

    def get_entries(self, eppn: str) -> List[Dict[str, Any]]:
        """
        :param eppn: User objects eduPersonPrincipalName property
        :return: A list of dicts
        """
        docs = self._get_documents_by_attr("eduPersonPrincipalName", eppn)
        return [self.model(doc) for doc in docs]
