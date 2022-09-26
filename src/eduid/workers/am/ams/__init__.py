"""
The eduID Attribute Manager package.

Copyright (c) 2013, 2014, 2015, 2018 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""
__author__ = 'eperez'

from typing import List

from bson import ObjectId
from celery.utils.log import get_task_logger

from eduid.userdb.actions.tou import ToUUserDB
from eduid.userdb.personal_data import PersonalDataUserDB
from eduid.userdb.proofing import (
    EidasProofingUserDB,
    EmailProofingUserDB,
    LetterProofingUserDB,
    LookupMobileProofingUserDB,
    OidcProofingUserDB,
    OrcidProofingUserDB,
    PhoneProofingUserDB,
)
from eduid.userdb.proofing.db import LadokProofingUserDB
from eduid.userdb.reset_password import ResetPasswordUserDB
from eduid.userdb.security import SecurityUserDB
from eduid.userdb.signup import SignupUserDB
from eduid.workers.am.ams.common import AttributeFetcher

logger = get_task_logger(__name__)


class eduid_signup(AttributeFetcher):

    whitelist_set_attrs = [
        'mail',
        'mailAliases',
        'eduPersonPrincipalName',
        'eppn',
        'passwords',
        'tou',
        # attributes for invites below
        'givenName',
        'surname',
        'displayName',
        'preferredLanguage',
        'phone',
        'identities',
    ]
    whitelist_unset_attrs: List[str] = []

    def fetch_attrs(self, user_id: ObjectId):
        attributes = AttributeFetcher.fetch_attrs(self, user_id)
        if '$set' not in attributes or 'passwords' not in attributes['$set']:
            logger.info(f'Not syncing signup user with attrs: {attributes}')
            raise ValueError('Not syncing user that has not completed signup')
        return attributes

    get_user_db = lambda cls, uri: SignupUserDB(uri)


class eduid_oidc_proofing(AttributeFetcher):

    whitelist_set_attrs = [
        # TODO: Arrays must use put or pop, not set, but need more deep refacts
        'nins',  # Old format
        'identities',  # New format
        'givenName',
        'surname',
        'displayName',
    ]
    whitelist_unset_attrs = [
        'identities',
        'nins',  # Old format
    ]
    get_user_db = lambda cls, uri: OidcProofingUserDB(uri)


class eduid_letter_proofing(AttributeFetcher):

    whitelist_set_attrs = [
        'nins',  # Old format
        'identities',  # New format
        'letter_proofing_data',
        'givenName',
        'surname',
        'displayName',
    ]
    whitelist_unset_attrs = [
        'identities',
        'nins',  # Old format
    ]
    get_user_db = lambda cls, uri: LetterProofingUserDB(uri)


class eduid_lookup_mobile_proofing(AttributeFetcher):

    whitelist_set_attrs = [
        'nins',  # Old format
        'identities',  # New format
        'givenName',
        'surname',
        'displayName',
    ]
    whitelist_unset_attrs = [
        'identities',
        'nins',  # Old format
    ]
    get_user_db = lambda cls, uri: LookupMobileProofingUserDB(uri)


class eduid_email(AttributeFetcher):

    whitelist_set_attrs = ['mailAliases']
    whitelist_unset_attrs = [
        'mailAliases',
    ]
    get_user_db = lambda cls, uri: EmailProofingUserDB(uri)


class eduid_phone(AttributeFetcher):

    whitelist_set_attrs = ['phone']
    whitelist_unset_attrs = [
        'phone',
    ]
    get_user_db = lambda cls, uri: PhoneProofingUserDB(uri)


class eduid_personal_data(AttributeFetcher):

    whitelist_set_attrs = [
        'givenName',
        'surname',
        'displayName',
        'preferredLanguage',
    ]
    get_user_db = lambda cls, uri: PersonalDataUserDB(uri)


class eduid_security(AttributeFetcher):

    whitelist_set_attrs = [
        'passwords',
        'terminated',
        'nins',  # Old format for AL1 downgrade on password reset
        'identities',  # For AL1 downgrade on password reset
        'phone',  # For AL1 downgrade on password reset
        'givenName',  # For updating user from official source (Navet)
        'surname',  # For updating user from official source (Navet)
        'displayName',  # For updating user from official source (Navet)
    ]
    whitelist_unset_attrs = [
        'passwords',
        'terminated',
        'nins',  # Old format for AL1 downgrade on password reset
        'identities',  # For AL1 downgrade on password reset
        'phone',  # For AL1 downgrade on password reset
    ]
    get_user_db = lambda cls, uri: SecurityUserDB(uri)


class eduid_reset_password(AttributeFetcher):

    whitelist_set_attrs = [
        'passwords',
        'terminated',  # For revoking termination status
        'nins',  # Old format for AL1 downgrade on password reset
        'identities',  # For AL1 downgrade on password reset
        'phone',  # For AL1 downgrade on password reset
    ]
    whitelist_unset_attrs = [
        'passwords',
        'terminated',  # For revoking termination status
        'nins',  # Old format for AL1 downgrade on password reset
        'identities',  # For AL1 downgrade on password reset
        'phone',  # For AL1 downgrade on password reset
    ]
    get_user_db = lambda cls, uri: ResetPasswordUserDB(uri)


class eduid_orcid(AttributeFetcher):

    whitelist_set_attrs = [
        'orcid',
    ]
    whitelist_unset_attrs = [
        'orcid',
    ]
    get_user_db = lambda cls, uri: OrcidProofingUserDB(uri)


class eduid_eidas(AttributeFetcher):

    whitelist_set_attrs = [
        'passwords',
        'nins',  # Old format
        'identities',
        'givenName',
        'surname',
        'displayName',
    ]
    whitelist_unset_attrs: List[str] = [
        'identities',
        'nins',  # Old format
    ]
    get_user_db = lambda cls, uri: EidasProofingUserDB(uri)


class eduid_tou(AttributeFetcher):

    whitelist_set_attrs = ['tou']
    whitelist_unset_attrs: List[str] = []
    get_user_db = lambda cls, uri: ToUUserDB(uri)


class eduid_ladok(AttributeFetcher):

    whitelist_set_attrs = [
        'ladok',
    ]
    whitelist_unset_attrs = [
        'ladok',
    ]
    get_user_db = lambda cls, uri: LadokProofingUserDB(uri)
