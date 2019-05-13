"""
The eduID Attribute Manager package.

Copyright (c) 2013, 2014, 2015, 2018 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""
__author__ = 'eperez'

from eduid_userdb.signup import SignupUserDB
from eduid_userdb.proofing import OidcProofingUserDB, LetterProofingUserDB
from eduid_userdb.proofing import EmailProofingUserDB, PhoneProofingUserDB
from eduid_userdb.proofing import EidasProofingUserDB, OrcidProofingUserDB
from eduid_userdb.proofing import LookupMobileProofingUserDB
from eduid_userdb.personal_data import PersonalDataUserDB
from eduid_userdb.security import SecurityUserDB
from eduid_userdb.actions.tou import ToUUserDB


from eduid_am.ams.common import AttributeFetcher

from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


class eduid_signup(AttributeFetcher):

    user_db_class = SignupUserDB
    whitelist_set_attrs = [
        'mail',
        'mailAliases',
        'eduPersonPrincipalName',
        'eppn',
        'passwords',
        'tou'
    ]
    whitelist_unset_attrs = [
    ]

    def __call__(self):
        attributes = super(OIDCProofingAF, self).__call__()
        if '$set' not in attributes or 'passwords' not in attributes['$set']:
            logger.info(f'Not syncing signup user with attrs: {attributes}')
            raise ValueError('Not syncing user that has not completed signup')
        return attributes



class eduid_oidc_proofing(AttributeFetcher):

    user_db_class = OidcProofingUserDB
    whitelist_set_attrs = [
        # TODO: Arrays must use put or pop, not set, but need more deep refacts
        'nins',  # New format
        'givenName',
        'surname',  # New format
        'displayName',
    ]
    whitelist_unset_attrs = [
        'norEduPersonNIN',
        'nins' # New format
    ]


class eduid_letter_proofing(AttributeFetcher):

    user_db_class = LetterProofingUserDB
    whitelist_set_attrs = [
        'nins',  # New format
        'letter_proofing_data',
        'givenName',
        'surname',  # New format
        'displayName',
    ]
    whitelist_unset_attrs = [
        'norEduPersonNIN',
        'nins' # New format
    ]


class eduid_lookup_mobile_proofing(AttributeFetcher):
    user_db_class = LookupMobileProofingUserDB
    whitelist_set_attrs = [
        'nins',  # New format
        'givenName',
        'surname',  # New format
        'displayName',
    ]
    whitelist_unset_attrs = [
        'norEduPersonNIN',
        'nins' # New format
    ]


class eduid_email(AttributeFetcher):
    user_db_class = EmailProofingUserDB
    whitelist_set_attrs = [
        'mailAliases'
    ]
    whitelist_unset_attrs = [
        'mailAliases',
        'mail', # Old format
    ]


class eduid_phone(AttributeFetcher):
    user_db_class = PhoneProofingUserDB
    whitelist_set_attrs = [
        'phone'
    ]
    whitelist_unset_attrs = [
        'phone',
        'mobile', # Old format
    ]


class eduid_personal_data(AttributeFetcher):
    user_db_class = PersonalDataUserDB
    whitelist_set_attrs = [
        'givenName',
        'surname',  # New format
        'displayName',
        'preferredLanguage',
    ]
    whitelist_unset_attrs = [
        'sn', # Old format
    ]


class eduid_security(AttributeFetcher):
    user_db_class = SecurityUserDB
    whitelist_set_attrs = [
        'passwords',
        'terminated',
        'nins',             # For AL1 downgrade on password reset
        'phone', # For AL1 downgrade on password reset
    ]
    whitelist_unset_attrs = [
        'passwords',
        'terminated',
        'norEduPersonNIN',  # For AL1 downgrade on password reset
        'nins',             # For AL1 downgrade on password reset
        'phone', # For AL1 downgrade on password reset
    ]


class eduid_orcid(AttributeFetcher):
    user_db_class = OrcidProofingUserDB
    whitelist_set_attrs = [
        'orcid',
    ]
    whitelist_unset_attrs = [
        'orcid',
    ]


class eduid_eidas(AttributeFetcher):
    user_db_class = EidasProofingUserDB
    whitelist_set_attrs = [
        'passwords',
        'nins',
        'givenName',
        'surname',  # New format
        'displayName',
    ]
    whitelist_unset_attrs = [
    ]


class eduid_tou(AttributeFetcher):

    user_db_class = ToUUserDB
    whitelist_set_attrs = [
        'tou'
    ]
    whitelist_unset_attrs = [
    ]
