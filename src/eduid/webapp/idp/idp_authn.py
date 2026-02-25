"""
Module handling authentication of users. Also applies login policies
such as rate limiting.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from http import HTTPStatus
from typing import Any

from bson import ObjectId
from pydantic import BaseModel, ConfigDict, Field
from pymongo import ReturnDocument

from eduid.common.misc.timeutil import utc_now
from eduid.userdb import MongoDB
from eduid.userdb.credentials import Password
from eduid.userdb.element import ElementKey
from eduid.userdb.idp import IdPUser, IdPUserDb
from eduid.userdb.maccapi import ManagedAccountDB
from eduid.vccs.client import VCCSClientHTTPError, VCCSPasswordFactor
from eduid.webapp.common.api import exceptions
from eduid.webapp.common.authn import get_vccs_client
from eduid.webapp.common.authn.vccs import upgrade_password_to_v2
from eduid.webapp.idp.settings.common import IdPConfig

logger = logging.getLogger(__name__)

OBJECT_ID_STRING_LENGTH = 24


class ExternalAuthnData(BaseModel):
    """Per-authentication remembered data about a used ExternalCredential"""

    issuer: str
    authn_context: str


class FidoAuthnData(BaseModel):
    user_present: bool = Field(default=False)
    user_verified: bool = Field(default=False)


class AuthnData(BaseModel):
    """
    Data about a successful authentication.

    Returned from functions performing authentication.
    """

    cred_id: ElementKey
    timestamp: datetime = Field(default_factory=utc_now, alias="authn_ts")  # authn_ts was the old name in the db
    external: ExternalAuthnData | None = None
    fido: FidoAuthnData | None = None
    model_config = ConfigDict(validate_by_alias=True, validate_by_name=True)

    def to_dict(self) -> dict[str, Any]:
        """Return the object in dict format (serialized for storing in MongoDB)."""
        return self.model_dump()

    @classmethod
    def from_dict(cls: type[AuthnData], data: Mapping[str, Any]) -> AuthnData:
        """Construct element from a data dict in database format."""
        return cls(**data)


class UsedWhere(StrEnum):
    REQUEST = "request"
    SSO = "SSO session"


# TODO: Maybe merge UsedCredential and AuthnData
class UsedCredential(BaseModel):
    credential_id: ElementKey
    ts: datetime
    external_authn_data: ExternalAuthnData | None = None
    fido_authn_data: FidoAuthnData | None = None
    source: UsedWhere

    def __str__(self) -> str:
        key = str(self.credential_id)
        if len(key) > OBJECT_ID_STRING_LENGTH:
            # 24 is length of object-id, webauthn credentials are much longer
            key = key[:21] + "..."
        return (
            f"<{self.__class__.__name__}: credential_id={key}), ts={self.ts.isoformat()}, source={self.source.value}>"
        )


@dataclass
class PasswordAuthnResponse:
    user: IdPUser
    credential: Password
    credentials_changed: bool = False
    timestamp: datetime = field(default_factory=utc_now)

    @property
    def authn_data(self) -> AuthnData:
        return AuthnData(cred_id=self.credential.key, timestamp=self.timestamp)


class IdPAuthn:
    """
    :param config: IdP configuration data
    """

    def __init__(
        self,
        config: IdPConfig,
        userdb: IdPUserDb,
        managed_account_db: ManagedAccountDB,
    ) -> None:
        self.config = config
        self.userdb = userdb
        self.managed_account_db = managed_account_db
        self.auth_client = get_vccs_client(config.vccs_url)
        # already checked with isinstance in app init
        assert config.mongo_uri is not None
        self.authn_store = AuthnInfoStore(uri=config.mongo_uri)

    def password_authn(self, username: str, password: str) -> PasswordAuthnResponse | None:
        """
        Authenticate someone using a username and password.

        :returns: The IdPUser found, and AuthnData on success
        """
        # check for managed user where username always starts with ma-
        if username.startswith("ma-"):
            user = self.managed_account_db.get_account_as_idp_user(username)
        else:
            user = self.userdb.lookup_user(username)

        if not user:
            return None

        # Snapshot credential keys before authentication to detect changes (e.g. v2 upgrade, v1 revocation)
        _cred_keys_before = {p.key for p in user.credentials.filter(Password)}

        cred = self._verify_username_and_password2(user, password)
        if not cred:
            return None

        _cred_keys_after = {p.key for p in user.credentials.filter(Password)}
        _credentials_changed = _cred_keys_after != _cred_keys_before

        return PasswordAuthnResponse(user=user, credential=cred, credentials_changed=_credentials_changed)

    def _verify_username_and_password2(self, user: IdPUser, password: str) -> Password | None:
        """
        Attempt to verify that a password is valid for a specific user.

        Currently, the naive approach of looping through all the users password credentials
        is taken. This is bad because the more passwords a user has, the more likely an
        online attacker is to guess any one of them.

        :return: IdPUser on successful authentication
        """
        pw_credentials = user.credentials.filter(Password)
        if self.authn_store:  # requires optional configuration
            if user.is_managed_account:
                logger.debug("Skipping authn_store, no credential failure check for managed accounts")
            else:
                authn_info = self.authn_store.get_user_authn_info(user)
                if authn_info.failures_this_month > self.config.max_authn_failures_per_month:
                    logger.info(
                        f"User {user!r} AuthN failures this month "
                        f"{authn_info.failures_this_month!r} > {self.config.max_authn_failures_per_month!r}"
                    )
                    raise exceptions.EduidTooManyRequests("Too Many Requests")

                # Optimize list of credentials to try based on which credentials the
                # user used in the last successful authentication. This optimization
                # is based on plain assumption, no measurements whatsoever.
                # Secondary sort: prefer v2 credentials over v1 (higher version first).
                last_creds = authn_info.last_used_credentials
                sorted_creds = sorted(
                    pw_credentials,
                    key=lambda x: (x.credential_id not in last_creds, -x.version),
                )
                if sorted_creds != pw_credentials:
                    logger.debug(
                        f"Re-sorted list of credentials into\n{sorted_creds}\nbased on last-used {last_creds!r}"
                    )
                    pw_credentials = sorted_creds

        return self._authn_passwords(user, password, pw_credentials)

    def _authn_passwords(self, user: IdPUser, password: str, pw_credentials: Sequence[Password]) -> Password | None:
        """
        Perform the final actual authentication of a user based on a list of (password) credentials.

        :param user: User object
        :param password: Password provided
        :param pw_credentials: Password credentials to try

        :return: Credential used, or None if authentication failed
        """
        for cred in pw_credentials:
            try:
                factor = VCCSPasswordFactor(password, str(cred.credential_id), str(cred.salt))
            except ValueError as exc:
                logger.info(f"User {user} password factor {cred.credential_id} unusable: {exc}")
                continue
            logger.debug(f"Password-authenticating {user}/{cred.credential_id} with VCCS: {factor}")
            user_id = str(user.user_id)
            try:
                if self.auth_client.authenticate(user_id, [factor]):
                    logger.debug(f"VCCS authenticated user {user}")
                    # Verify that the credential had been successfully used in the last 18 months
                    # (Kantara AL2_CM_CSM#050).
                    if self.credential_expired(cred):
                        logger.info(f"User {user} credential {cred.key} has expired")
                        raise exceptions.EduidForbidden("CREDENTIAL_EXPIRED")
                    self.log_authn(user, success=[cred.credential_id], failure=[])
                    # Transparently upgrade v1 password to v2 (NDNv2) if enabled
                    if self.config.password_v2_upgrade_enabled and cred.version == 1:
                        _has_v2 = any(p.version == 2 for p in user.credentials.filter(Password))  # noqa: PLR2004
                        if not _has_v2:
                            if not upgrade_password_to_v2(
                                user=user,
                                password=password,
                                old_credential=cred,
                                application="idp",
                                vccs=self.auth_client,
                            ):
                                logger.warning(f"Password v2 upgrade failed for user {user}")
                    return cred
            except VCCSClientHTTPError as exc:
                if exc.http_code == HTTPStatus.INTERNAL_SERVER_ERROR:
                    logger.debug(f"VCCS credential {cred.credential_id} might be revoked")
                    continue
        logger.debug(f"VCCS username-password authentication FAILED for user {user}")
        self.log_authn(user, success=[], failure=[cred.credential_id for cred in pw_credentials])
        return None

    def credential_expired(self, cred: Password) -> bool:
        """
        Check that a credential hasn't been unused for too long according to Kantara AL2_CM_CSM#050.
        :param cred: Authentication credential
        """
        if not self.authn_store:  # requires optional configuration
            logger.debug(f"Can't check if credential {cred.key} is expired, no authn_store available")
            return False
        last_used = self.authn_store.get_credential_last_used(cred.credential_id)
        if last_used is None:
            # Can't disallow this while there is a short-path from signup to dashboard unforch...
            logger.debug(f"Allowing never-used credential {cred!r}")
            return False
        now = utc_now()
        delta = now - last_used
        logger.debug(f"Credential {cred.key} last used {delta.days} days ago")
        return delta.days >= int(365 * 1.5)

    def log_authn(self, user: IdPUser, success: Sequence[str], failure: Sequence[str]) -> None:
        """
        Log user authn success as well as failures.

        :param user: User
        :param success: List of successfully authenticated credentials
        :param failure: List of failed credentials
        """
        if user.is_managed_account:
            logger.debug("Skipping logging to the authn store for managed accounts")
            return None
        if not self.authn_store:  # requires optional configuration
            return None
        if success:
            self.authn_store.credential_success(success)
        if success or failure:
            self.authn_store.update_user(user.user_id, success, failure)
        return None


class AuthnInfoStore:
    """
    In this database, information about users have ObjectId _id's corresponding to user.user_id,
    and information about credentials have string _id's.

    Example:

      User info:

        {
                "_id" : ObjectId("5fc5f6a318e93a5e90212c0e"),
                "success_ts" : ISODate("2020-12-01T07:54:24.309Z"),
                "last_credential_ids" : [
                        "5fc5f6ab18e93a5e90212c11"
                ],
                "fail_count" : {
                        "202012" : 0
                },
                "success_count" : {
                        "202012" : 1
                }
        }

      Credential info:

        {
                "_id" : "5fc5f74618e93a5e90212c16",
                "success_ts" : ISODate("2020-12-01T07:56:58.665Z")
        }
    """

    def __init__(self, uri: str, db_name: str = "eduid_idp_authninfo", collection_name: str = "authn_info") -> None:
        logger.debug("Setting up AuthnInfoStore")
        self._db = MongoDB(db_uri=uri, db_name=db_name)
        self.collection = self._db.get_collection(collection_name)

    def credential_success(self, cred_ids: Sequence[str], ts: datetime | None = None) -> None:
        """
        Kantara AL2_CM_CSM#050 requires that any credential that is not used for
        a period of 18 months is disabled (taken to mean revoked).

        Therefore we need to log all successful authentications and have a cron
        job handling the revoking of unused credentials.

        :param cred_ids: List of Credential ID
        :param ts: Optional timestamp
        :return: None
        """
        if ts is None:
            ts = utc_now()
        # Update all existing entries in one go would've been nice, but pymongo does not
        # return meaningful data for multi=True, so it is not possible to figure out
        # which entries were actually updated :(
        for this in cred_ids:
            self.collection.update_one(
                filter={"_id": this}, update={"$set": {"_id": this, "success_ts": ts}}, upsert=True
            )

    def update_user(
        self, user_id: ObjectId, success: Sequence[str], failure: Sequence[str], ts: datetime | None = None
    ) -> None:
        """
        Log authentication result data for this user.

        The fail_count.month is logged to be able to lock users out after too
        many failed authentication attempts in a month (yet unspecific Kantara
        requirement).

        The success_count.month is logged for symmetry.

        The last_credential_ids are logged so that the IdP can sort
        the list of credentials giving preference to these the next
        time, to not load down the authentication backends with
        authentication requests for credentials the user might not
        be using (as often).

        :param user_id: User identifier
        :param success: List of Credential Ids successfully authenticated
        :param failure: List of Credential Ids for which authentication failed
        :param ts: Optional timestamp
        """
        if ts is None:
            ts = utc_now()
        this_month = (ts.year * 100) + ts.month  # format year-month as integer (e.g. 201402)
        self.collection.find_one_and_update(
            filter={"_id": user_id},
            update={
                "$set": {"success_ts": ts, "last_credential_ids": success},
                "$inc": {f"fail_count.{this_month}": len(failure), f"success_count.{this_month}": len(success)},
            },
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )

    def unlock_user(self, user_id: ObjectId, fail_count: int = 0, ts: datetime | None = None) -> None:
        """
        Set the fail count for a specific user and month.

        Used from the CLI `unlock_user`.

        :param user_id: User identifier
        :param fail_count: Number of failed attempts to put the user at
        :param ts: Optional timestamp
        """
        if ts is None:
            ts = utc_now()
        this_month = (ts.year * 100) + ts.month  # format year-month as integer (e.g. 201402)
        self.collection.find_one_and_update(
            filter={"_id": user_id},
            update={"$set": {f"fail_count.{this_month}": fail_count}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )

    def get_user_authn_info(self, user: IdPUser) -> UserAuthnInfo:
        """Load stored Authn information for user."""
        docs = list(self.collection.find({"_id": user.user_id}))
        if len(docs) == 0:
            return UserAuthnInfo(failures_this_month=0, last_used_credentials=[])
        return UserAuthnInfo.from_dict(docs[0])

    def get_credential_last_used(self, cred_id: str) -> datetime | None:
        """Get the timestamp for when a specific credential was last used successfully.

        :return: Time of last successful use, or None
        """
        # Locate documents written by credential_success() above
        docs = list(self.collection.find({"_id": cred_id}))
        if len(docs) == 0:
            return None
        _success_ts = docs[0]["success_ts"]
        if not isinstance(_success_ts, datetime):
            raise ValueError(f"success_ts is not a datetime ({_success_ts!r})")
        return _success_ts


@dataclass(frozen=True)
class UserAuthnInfo:
    """
    Interpret data about a user loaded from the AuthnInfoStore.
    """

    failures_this_month: int
    last_used_credentials: list[str]

    @classmethod
    def from_dict(cls: type[UserAuthnInfo], data: dict[str, Any], ts: datetime | None = None) -> UserAuthnInfo:
        """Construct element from a data dict in database format."""
        data = dict(data)  # to not modify callers data

        if ts is None:
            ts = utc_now()
        this_month = (ts.year * 100) + ts.month  # format year-month as integer (e.g. 201402)

        _fail_count = data.get("fail_count", {})
        failures_this_month = _fail_count.get(str(this_month), 0)
        last_used_credentials = data.get("last_credential_ids", [])

        return cls(failures_this_month=failures_this_month, last_used_credentials=last_used_credentials)
