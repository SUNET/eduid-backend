# -*- coding: utf-8 -*-

from __future__ import absolute_import

from bson import ObjectId

from eduid_userdb.userdb import BaseDB, UserDB
from eduid_userdb.dashboard.userdb import DashboardUserDB
from eduid_userdb.signup.userdb import SignupUserDB
from eduid_userdb.support import models

__author__ = 'lundberg'

"""
Database classes for use in support applications to filter user data returned to support personnel. This
way we can minimize the risk of accidentally sharing any secret user data.
"""


class SupportUserDB(UserDB):

    UserClass = SupportUser

    def __init__(self, db_uri, db_name='eduid_am', collection='attributes', user_class=None):
        super(SupportUserDB, self).__init__(db_uri, db_name, collection, user_class)

    def search_users(self, query):
        """
        :param query: search query, can be a user eppn, nin, mail address or phone number
        :type query: str | unicode
        :return: A list of SupportUser objects
        :rtype: list
        """
        results = list()
        # We could do this with a custom filter (and one db call) but it is better to lean on existing methods
        # if the way we find users change in the future
        results.append(self.get_user_by_eppn(query, raise_on_missing=False))
        results.append(self.get_user_by_nin(query, raise_on_missing=False))
        results.extend(self.get_user_by_mail(query, raise_on_missing=False, return_list=True))
        results.extend(self.get_user_by_phone(query, raise_on_missing=False, return_list=True))
        users = list(set([user for user in results if user]))
        return users


class SupportDashboardUserDB(DashboardUserDB):

    UserClass = models.SupportDashboardUser


class SupportSignupUserDB(SignupUserDB):

    UserClass = models.SupportSignupUser


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
        :rtype: dict | None
        """
        if not isinstance(user_id, ObjectId):
            user_id = ObjectId(user_id)
        doc = self._get_document_by_attr('user_oid', user_id, raise_on_missing=False)
        if doc:
            doc = self.model(doc)
        return doc


class SupportVerificationsDB(BaseDB):

    model = models.UserVerifications

    def __init__(self, db_uri):
        db_name = 'eduid_dashboard'
        collection = 'verifications'
        super(SupportVerificationsDB, self).__init__(db_uri, db_name, collection)

    def get_verifications(self, user_id):
        """
        :param user_id: User objects user_id property
        :type user_id: ObjectId | str | unicode
        :return: A document dict
        :rtype: dict | None
        """
        if not isinstance(user_id, ObjectId):
            user_id = ObjectId(user_id)
        docs = self._get_documents_by_attr('user_oid', user_id, raise_on_missing=False)
        return [self.model(doc) for doc in docs]


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
        :return: A document dict
        :rtype: dict | None
        """
        if not isinstance(user_id, ObjectId):
            user_id = ObjectId(user_id)
        docs = self._get_documents_by_attr('user_oid', user_id, raise_on_missing=False)
        return [self.model(doc) for doc in docs]
