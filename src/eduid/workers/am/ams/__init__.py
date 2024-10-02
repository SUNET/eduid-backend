"""
The eduID Attribute Manager package.

Copyright (c) 2013, 2014, 2015, 2018 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""

__author__ = "eperez"


from typing import Any

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
from eduid.userdb.proofing.db import (
    BankIDProofingUserDB,
    FrejaEIDProofingUserDB,
    LadokProofingUserDB,
    SvideIDProofingUserDB,
)
from eduid.userdb.reset_password import ResetPasswordUserDB
from eduid.userdb.security import SecurityUserDB
from eduid.userdb.signup import SignupUserDB
from eduid.userdb.user_cleaner.userdb import CleanerUserDB
from eduid.workers.am.ams.common import AttributeFetcher

logger = get_task_logger(__name__)


class eduid_signup(AttributeFetcher):
    whitelist_set_attrs = [
        "givenName",
        "surname",
        "mail",
        "mailAliases",
        "eduPersonPrincipalName",
        "eppn",
        "passwords",
        "tou",
        # attributes for invites below
        "preferredLanguage",
        "phone",
        "identities",
    ]
    whitelist_unset_attrs: list[str] = []

    def fetch_attrs(self, user_id: ObjectId) -> dict[str, Any]:
        attributes = AttributeFetcher.fetch_attrs(self, user_id)
        if "$set" not in attributes or "passwords" not in attributes["$set"]:
            logger.info(f"Not syncing signup user with attrs: {attributes}")
            raise ValueError("Not syncing user that has not completed signup")
        return attributes

    @classmethod
    def get_user_db(cls, uri: str) -> SignupUserDB:
        return SignupUserDB(uri)


class eduid_oidc_proofing(AttributeFetcher):
    whitelist_set_attrs = [
        # TODO: Arrays must use put or pop, not set, but need more deep refacts
        "nins",  # Old format
        "identities",  # New format
        "givenName",
        "chosen_given_name",
        "surname",
        "legal_name",
    ]
    whitelist_unset_attrs = [
        "identities",
        "chosen_given_name",
        "nins",  # Old format
        "displayName",  # deprecated
    ]

    @classmethod
    def get_user_db(cls, uri: str) -> OidcProofingUserDB:
        return OidcProofingUserDB(uri)


class eduid_letter_proofing(AttributeFetcher):
    whitelist_set_attrs = [
        "nins",  # Old format
        "identities",  # New format
        "letter_proofing_data",
        "givenName",
        "chosen_given_name",
        "surname",
        "legal_name",
    ]
    whitelist_unset_attrs = [
        "identities",
        "chosen_given_name",
        "nins",  # Old format
        "displayName",  # deprecated
    ]

    @classmethod
    def get_user_db(cls, uri: str) -> LetterProofingUserDB:
        return LetterProofingUserDB(uri)


class eduid_lookup_mobile_proofing(AttributeFetcher):
    whitelist_set_attrs = [
        "nins",  # Old format
        "identities",  # New format
        "givenName",
        "chosen_given_name",
        "surname",
        "legal_name",
    ]
    whitelist_unset_attrs = [
        "identities",
        "chosen_given_name",
        "nins",  # Old format
        "displayName",  # deprecated
    ]

    @classmethod
    def get_user_db(cls, uri: str) -> LookupMobileProofingUserDB:
        return LookupMobileProofingUserDB(uri)


class eduid_email(AttributeFetcher):
    whitelist_set_attrs = ["mailAliases"]
    whitelist_unset_attrs = [
        "mailAliases",
    ]

    @classmethod
    def get_user_db(cls, uri: str) -> EmailProofingUserDB:
        return EmailProofingUserDB(uri)


class eduid_phone(AttributeFetcher):
    whitelist_set_attrs = ["phone"]
    whitelist_unset_attrs = [
        "phone",
    ]

    @classmethod
    def get_user_db(cls, uri: str) -> PhoneProofingUserDB:
        return PhoneProofingUserDB(uri)


class eduid_personal_data(AttributeFetcher):
    whitelist_set_attrs = [
        "givenName",
        "chosen_given_name",
        "surname",
        "preferredLanguage",
        "preferences",
    ]

    whitelist_unset_attrs = [
        "chosen_given_name",
        "displayName",  # deprecated
    ]

    @classmethod
    def get_user_db(cls, uri: str) -> PersonalDataUserDB:
        return PersonalDataUserDB(uri)


class eduid_security(AttributeFetcher):
    whitelist_set_attrs = [
        "passwords",
        "terminated",
        "nins",  # Old format for AL1 downgrade on password reset
        "identities",  # For AL1 downgrade on password reset
        "phone",  # For AL1 downgrade on password reset
        "givenName",  # For updating user from official source (Navet)
        "chosen_given_name",  # For updating user from official source (Navet)
        "surname",  # For updating user from official source (Navet)
        "legal_name",  # For updating user from official source (Navet)
    ]
    whitelist_unset_attrs = [
        "passwords",
        "terminated",
        "nins",  # Old format for AL1 downgrade on password reset
        "identities",  # For AL1 downgrade on password reset
        "phone",  # For AL1 downgrade on password reset
        "displayName",  # deprecated
    ]

    @classmethod
    def get_user_db(cls, uri: str) -> SecurityUserDB:
        return SecurityUserDB(uri)


class eduid_reset_password(AttributeFetcher):
    whitelist_set_attrs = [
        "passwords",
        "terminated",  # For revoking termination status
        "nins",  # Old format for AL1 downgrade on password reset
        "identities",  # For AL1 downgrade on password reset
        "phone",  # For AL1 downgrade on password reset
    ]
    whitelist_unset_attrs = [
        "passwords",
        "terminated",  # For revoking termination status
        "nins",  # Old format for AL1 downgrade on password reset
        "identities",  # For AL1 downgrade on password reset
        "phone",  # For AL1 downgrade on password reset
    ]

    @classmethod
    def get_user_db(cls, uri: str) -> ResetPasswordUserDB:
        return ResetPasswordUserDB(uri)


class eduid_orcid(AttributeFetcher):
    whitelist_set_attrs = [
        "orcid",
    ]
    whitelist_unset_attrs = [
        "orcid",
    ]

    @classmethod
    def get_user_db(cls, uri: str) -> OrcidProofingUserDB:
        return OrcidProofingUserDB(uri)


class eduid_eidas(AttributeFetcher):
    whitelist_set_attrs = [
        "passwords",
        "nins",  # Old format
        "identities",
        "givenName",
        "chosen_given_name",
        "surname",
        "legal_name",
    ]
    whitelist_unset_attrs: list[str] = [
        "identities",
        "chosen_given_name",
        "nins",  # Old format
        "displayName",  # deprecated
    ]

    @classmethod
    def get_user_db(cls, uri: str) -> EidasProofingUserDB:
        return EidasProofingUserDB(uri)


class eduid_tou(AttributeFetcher):
    whitelist_set_attrs = ["tou"]
    whitelist_unset_attrs: list[str] = []

    @classmethod
    def get_user_db(cls, uri: str) -> ToUUserDB:
        return ToUUserDB(uri)


class eduid_ladok(AttributeFetcher):
    whitelist_set_attrs = [
        "ladok",
    ]
    whitelist_unset_attrs = [
        "ladok",
    ]

    @classmethod
    def get_user_db(cls, uri: str) -> LadokProofingUserDB:
        return LadokProofingUserDB(uri)


class eduid_svipe_id(AttributeFetcher):
    whitelist_set_attrs = [
        "passwords",
        "identities",
        "givenName",
        "chosen_given_name",
        "surname",
        "legal_name",
    ]
    whitelist_unset_attrs: list[str] = [
        "identities",
        "chosen_given_name",
        "nins",  # Old format
        "displayName",  # deprecated
    ]

    @classmethod
    def get_user_db(cls, uri: str) -> SvideIDProofingUserDB:
        return SvideIDProofingUserDB(uri)


class eduid_bankid(AttributeFetcher):
    whitelist_set_attrs = [
        "passwords",
        "nins",  # Old format
        "identities",
        "givenName",
        "chosen_given_name",
        "surname",
        "legal_name",
    ]
    whitelist_unset_attrs: list[str] = [
        "identities",
        "chosen_given_name",
        "nins",  # Old format
        "displayName",  # deprecated
    ]

    @classmethod
    def get_user_db(cls, uri: str) -> BankIDProofingUserDB:
        return BankIDProofingUserDB(uri)


class eduid_freja_eid(AttributeFetcher):
    whitelist_set_attrs = [
        "passwords",
        "identities",
        "givenName",
        "chosen_given_name",
        "surname",
        "legal_name",
    ]
    whitelist_unset_attrs: list[str] = [
        "identities",
        "chosen_given_name",
        "nins",  # Old format
        "displayName",  # deprecated
    ]

    @classmethod
    def get_user_db(cls, uri: str) -> FrejaEIDProofingUserDB:
        return FrejaEIDProofingUserDB(uri)


class eduid_job_runner(AttributeFetcher):
    whitelist_set_attrs = ["terminated"]  # skv cleaner checks status of registered persons

    @classmethod
    def get_user_db(cls, uri: str) -> CleanerUserDB:
        return CleanerUserDB(uri)
