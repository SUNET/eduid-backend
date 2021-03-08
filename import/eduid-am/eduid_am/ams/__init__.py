"""
The eduID Attribute Manager package.

Copyright (c) 2013, 2014, 2015, 2018 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""
__author__ = 'eperez'

from typing import List

from celery.utils.log import get_task_logger

from eduid_userdb.actions.tou import ToUUserDB
from eduid_userdb.personal_data import PersonalDataUserDB
from eduid_userdb.proofing import (
    EidasProofingUserDB,
    EmailProofingUserDB,
    LetterProofingUserDB,
    LookupMobileProofingUserDB,
    OidcProofingUserDB,
    OrcidProofingUserDB,
    PhoneProofingUserDB,
)
from eduid_userdb.reset_password import ResetPasswordUserDB
from eduid_userdb.security import SecurityUserDB
from eduid_userdb.signup import SignupUserDB

from eduid_am.ams.common import AttributeFetcher

logger = get_task_logger(__name__)


class eduid_signup(AttributeFetcher):

    whitelist_set_attrs = ['mail', 'mailAliases', 'eduPersonPrincipalName', 'eppn', 'passwords', 'tou']
    whitelist_unset_attrs: List[str] = []

    def fetch_attrs(self, user_id):
        attributes = AttributeFetcher.fetch_attrs(self, user_id)
        if '$set' not in attributes or 'passwords' not in attributes['$set']:
            logger.info(f'Not syncing signup user with attrs: {attributes}')
            raise ValueError('Not syncing user that has not completed signup')
        return attributes

    get_user_db = lambda cls, uri: SignupUserDB(uri)


class eduid_oidc_proofing(AttributeFetcher):

    whitelist_set_attrs = [
        # TODO: Arrays must use put or pop, not set, but need more deep refacts
        'nins',  # New format
        'givenName',
        'surname',  # New format
        'displayName',
    ]
    whitelist_unset_attrs = ['norEduPersonNIN', 'nins']  # New format
    get_user_db = lambda cls, uri: OidcProofingUserDB(uri)


class eduid_letter_proofing(AttributeFetcher):

    whitelist_set_attrs = [
        'nins',  # New format
        'letter_proofing_data',
        'givenName',
        'surname',  # New format
        'displayName',
    ]
    whitelist_unset_attrs = ['norEduPersonNIN', 'nins']  # New format
    get_user_db = lambda cls, uri: LetterProofingUserDB(uri)


class eduid_lookup_mobile_proofing(AttributeFetcher):

    whitelist_set_attrs = [
        'nins',  # New format
        'givenName',
        'surname',  # New format
        'displayName',
    ]
    whitelist_unset_attrs = ['norEduPersonNIN', 'nins']  # New format
    get_user_db = lambda cls, uri: LookupMobileProofingUserDB(uri)


class eduid_email(AttributeFetcher):

    whitelist_set_attrs = ['mailAliases']
    whitelist_unset_attrs = [
        'mailAliases',
        'mail',  # Old format
    ]
    get_user_db = lambda cls, uri: EmailProofingUserDB(uri)


class eduid_phone(AttributeFetcher):

    whitelist_set_attrs = ['phone']
    whitelist_unset_attrs = [
        'phone',
        'mobile',  # Old format
    ]
    get_user_db = lambda cls, uri: PhoneProofingUserDB(uri)


class eduid_personal_data(AttributeFetcher):

    whitelist_set_attrs = [
        'givenName',
        'surname',  # New format
        'displayName',
        'preferredLanguage',
    ]
    whitelist_unset_attrs = [
        'sn',  # Old format
    ]
    get_user_db = lambda cls, uri: PersonalDataUserDB(uri)


class eduid_security(AttributeFetcher):

    whitelist_set_attrs = [
        'passwords',
        'terminated',
        'nins',  # For AL1 downgrade on password reset
        'phone',  # For AL1 downgrade on password reset
    ]
    whitelist_unset_attrs = [
        'passwords',
        'terminated',
        'norEduPersonNIN',  # For AL1 downgrade on password reset
        'nins',  # For AL1 downgrade on password reset
        'phone',  # For AL1 downgrade on password reset
    ]
    get_user_db = lambda cls, uri: SecurityUserDB(uri)


class eduid_reset_password(AttributeFetcher):

    whitelist_set_attrs = [
        'passwords',
        'nins',  # For AL1 downgrade on password reset
        'phone',  # For AL1 downgrade on password reset
    ]
    whitelist_unset_attrs = [
        'passwords',
        'norEduPersonNIN',  # For AL1 downgrade on password reset
        'nins',  # For AL1 downgrade on password reset
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
        'nins',
        'givenName',
        'surname',  # New format
        'displayName',
    ]
    whitelist_unset_attrs: List[str] = []
    get_user_db = lambda cls, uri: EidasProofingUserDB(uri)


class eduid_tou(AttributeFetcher):

    whitelist_set_attrs = ['tou']
    whitelist_unset_attrs: List[str] = []
    get_user_db = lambda cls, uri: ToUUserDB(uri)


## XXX remove after https://github.com/SUNET/eduid-am/pull/32 is merged
tou = eduid_tou
