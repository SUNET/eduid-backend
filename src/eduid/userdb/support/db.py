# -*- coding: utf-8 -*-

from typing import Any, List, Mapping, Type

from bson import ObjectId

from eduid.userdb.signup import SignupUserDB
from eduid.userdb.support import models
from eduid.userdb.support.models import GenericFilterDict
from eduid.userdb.support.user import SupportSignupUser, SupportUser
from eduid.userdb.userdb import BaseDB, UserDB

__author__ = 'lundberg'

"""
Database classes for use in support applications to filter user data returned to support personnel. This
way we can minimize the risk of accidentally sharing any secret user data.
"""


class SupportUserDB(UserDB[SupportUser]):
    def __init__(self, db_uri: str, db_name: str = 'eduid_am', collection: str = 'attributes'):
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
        results.append(self.get_user_by_eppn(query, raise_on_missing=False))
        results.append(self.get_user_by_nin(query, raise_on_missing=False))
        results.extend(self.get_user_by_mail(query, raise_on_missing=False, return_list=True))
        results.extend(self.get_user_by_phone(query, raise_on_missing=False, return_list=True))
        users = [user for user in results if user]
        return users


class SupportSignupUserDB(SignupUserDB):

    UserClass = SupportSignupUser


class SupportAuthnInfoDB(BaseDB):

    model = models.UserAuthnInfo

    def __init__(self, db_uri):
        db_name = 'eduid_idp_authninfo'
        collection = 'authn_info'
        super(SupportAuthnInfoDB, self).__init__(db_uri, db_name, collection)

    def get_authn_info(self, user_id):
        """
        :param user_id: User objects user_id property
        :type user_id: ObjectId | str | unicode
        :return: A document dict
        :rtype: dict
        """
        if not isinstance(user_id, ObjectId):
            user_id = ObjectId(user_id)
        docs = self._get_documents_by_filter({'_id': user_id}, raise_on_missing=False)
        if not docs:
            return dict()
        return self.model(dict(docs[0]))  # Cast to dict to allow mutability

    def get_credential_info(self, credential_id):
        """
        :param credential_id: Credential id
        :type credential_id: str | unicode
        :return:  A document dict
        :rtype: dict
        """
        doc = self._get_document_by_attr('_id', credential_id, raise_on_missing=False)
        if not doc:
            return dict()
        return self.model(dict(doc))  # Cast to dict to allow mutability


class SupportActionsDB(BaseDB):

    model = models.UserActions

    def __init__(self, db_uri):
        db_name = 'eduid_actions'
        collection = 'actions'
        super(SupportActionsDB, self).__init__(db_uri, db_name, collection)

    def get_actions(self, user_id):
        """
        :param user_id: User objects user_id property
        :type user_id: ObjectId | str | unicode
        :return: A list of dicts
        :rtype: list
        """
        if not isinstance(user_id, ObjectId):
            user_id = ObjectId(user_id)
        docs = self._get_documents_by_filter(spec={'user_oid': user_id}, raise_on_missing=False)
        return [self.model(dict(doc)) for doc in docs]  # Cast to dict to allow mutability


class SupportProofingDB(BaseDB):

    model: Type[GenericFilterDict] = GenericFilterDict

    def __init__(self, db_uri, db_name, collection):
        super(SupportProofingDB, self).__init__(db_uri, db_name, collection)

    def get_proofing_state(self, eppn):
        """
        :param eppn: User objects eduPersonPrincipalName property
        :type eppn: str | unicode
        :return: A document dict
        :rtype: dict
        """
        doc = self._get_document_by_attr('eduPersonPrincipalName', eppn, raise_on_missing=False)
        if not doc:
            return dict()
        return self.model(dict(doc))  # Cast to dict to allow mutability

    def get_proofing_states(self, eppn):
        """
        :param eppn: User objects eduPersonPrincipalName property
        :type eppn: str | unicode
        :return: A list of document dicts
        :rtype: list
        """
        docs = self._get_documents_by_attr('eduPersonPrincipalName', eppn, raise_on_missing=False)
        return [self.model(dict(doc)) for doc in docs]  # Cast to dict to allow mutability


class SupportLetterProofingDB(SupportProofingDB):

    model = models.UserLetterProofing

    def __init__(self, db_uri):
        db_name = 'eduid_idproofing_letter'
        collection = 'proofing_data'
        super(SupportLetterProofingDB, self).__init__(db_uri, db_name, collection)


class SupportOidcProofingDB(SupportProofingDB):

    model = models.UserOidcProofing

    def __init__(self, db_uri):
        db_name = 'eduid_oidc_proofing'
        collection = 'proofing_data'
        super(SupportOidcProofingDB, self).__init__(db_uri, db_name, collection)


class SupportEmailProofingDB(SupportProofingDB):

    model = models.UserEmailProofing

    def __init__(self, db_uri):
        db_name = 'eduid_email'
        collection = 'proofing_data'
        super(SupportEmailProofingDB, self).__init__(db_uri, db_name, collection)


class SupportPhoneProofingDB(SupportProofingDB):

    model = models.UserPhoneProofing

    def __init__(self, db_uri):
        db_name = 'eduid_phone'
        collection = 'proofing_data'
        super(SupportPhoneProofingDB, self).__init__(db_uri, db_name, collection)


class SupportProofingLogDB(BaseDB):

    model = models.ProofingLogEntry

    def __init__(self, db_uri):
        db_name = 'eduid_logs'
        collection = 'proofing_log'
        super(SupportProofingLogDB, self).__init__(db_uri, db_name, collection)

    def get_entries(self, eppn):
        """
        :param eppn: User objects eduPersonPrincipalName property
        :type eppn: str | unicode
        :return: A list of dicts
        :rtype: list
        """
        docs = self._get_documents_by_attr('eduPersonPrincipalName', eppn, raise_on_missing=False)
        return [self.model(doc) for doc in docs]
