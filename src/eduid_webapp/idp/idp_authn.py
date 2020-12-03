#
# Copyright (c) 2014 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#

"""
Module handling authentication of users. Also applies login policies
such as rate limiting.
"""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Type

from bson import ObjectId

from eduid_common.api import exceptions
from eduid_common.authn import get_vccs_client
from eduid_common.config.idp import IdPConfig
from eduid_common.misc.timeutil import utc_now
from eduid_userdb import MongoDB
from eduid_userdb.credentials import Credential, Password
from eduid_userdb.exceptions import UserHasNotCompletedSignup
from eduid_userdb.idp import IdPUser, IdPUserDb
from vccs_client import VCCSClientHTTPError, VCCSPasswordFactor

logger = logging.getLogger(__name__)


@dataclass
class AuthnData(object):
    """
    Data about a successful authentication.

    Returned from functions performing authentication.
    """

    cred_id: str
    timestamp: datetime = field(default_factory=utc_now)
    user: Optional[IdPUser] = None  # not set if object is created from database

    def to_dict(self) -> Dict[str, Any]:
        """ Return the object in dict format (serialized for storing in MongoDB). """
        res = asdict(self)
        del res['user']
        return res

    @classmethod
    def from_dict(cls: Type[AuthnData], data: Dict[str, Any]) -> AuthnData:
        """ Construct element from a data dict in database format. """
        return cls(**data)


class IdPAuthn(object):
    """
    :param config: IdP configuration data

    :type config: IdPConfig
    """

    def __init__(
        self, config: IdPConfig, userdb: IdPUserDb,
    ):
        self.config = config
        self.userdb = userdb
        self.auth_client = get_vccs_client(config.vccs_url)
        self.authn_store = AuthnInfoStore(uri=config.mongo_uri)

    def password_authn(self, data: Dict[str, Any]) -> Optional[AuthnData]:
        """
        Authenticate someone using a username and password.

        :param data: Login credentials (dict with 'username' and 'password')
        :returns: AuthnData on success
        """
        username = data['username']
        password = data['password']
        del data  # keep sensitive data out of Sentry logs

        try:
            user = self.userdb.lookup_user(username)
        except UserHasNotCompletedSignup:
            # XXX Redirect user to some kind of info page
            return None
        if not user:
            logger.info('Unknown user : {!r}'.format(username))
            # XXX we effectively disclose there was no such user by the quick
            # response in this case. Maybe send bogus auth request to backends?
            return None
        logger.debug(f'Found user {user}')

        cred = self._verify_username_and_password2(user, password)
        if not cred:
            return None

        return AuthnData(cred_id=cred.key, user=user)

    def _verify_username_and_password2(self, user: IdPUser, password: str) -> Optional[Password]:
        """
        Attempt to verify that a password is valid for a specific user.

        Currently, the naive approach of looping through all the users password credentials
        is taken. This is bad because the more passwords a user has, the more likely an
        online attacker is to guess any one of them.

        :return: IdPUser on successful authentication

        :rtype: Credential | None
        """
        pw_credentials = user.credentials.filter(Password).to_list()
        if self.authn_store:  # requires optional configuration
            authn_info = self.authn_store.get_user_authn_info(user)
            if authn_info.failures_this_month > self.config.max_authn_failures_per_month:
                logger.info(
                    "User {!r} AuthN failures this month {!r} > {!r}".format(
                        user, authn_info.failures_this_month, self.config.max_authn_failures_per_month
                    )
                )
                raise exceptions.EduidTooManyRequests("Too Many Requests")

            # Optimize list of credentials to try based on which credentials the
            # user used in the last successful authentication. This optimization
            # is based on plain assumption, no measurements whatsoever.
            last_creds = authn_info.last_used_credentials
            sorted_creds = sorted(pw_credentials, key=lambda x: x.credential_id not in last_creds)
            if sorted_creds != pw_credentials:
                logger.debug(
                    "Re-sorted list of credentials into\n{}\nbased on last-used {!r}".format(sorted_creds, last_creds)
                )
                pw_credentials = sorted_creds

        return self._authn_passwords(user, password, pw_credentials)

    def _authn_passwords(self, user: IdPUser, password: str, pw_credentials: Sequence[Password]) -> Optional[Password]:
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
                logger.info(f'User {user} password factor {cred.credential_id} unusable: {exc}')
                continue
            logger.debug(f"Password-authenticating {user}/{cred.credential_id} with VCCS: {factor}")
            user_id = str(user.user_id)
            try:
                if self.auth_client.authenticate(user_id, [factor]):
                    logger.debug(f'VCCS authenticated user {user}')
                    # Verify that the credential had been successfully used in the last 18 months
                    # (Kantara AL2_CM_CSM#050).
                    if self.credential_expired(cred):
                        logger.info(f'User {user} credential {cred.key} has expired')
                        raise exceptions.EduidForbidden('CREDENTIAL_EXPIRED')
                    self.log_authn(user, success=[cred.credential_id], failure=[])
                    return cred
            except VCCSClientHTTPError as exc:
                if exc.http_code == 500:
                    logger.debug(f'VCCS credential {cred.credential_id} might be revoked')
                    continue
        logger.debug(f'VCCS username-password authentication FAILED for user {user}')
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
            logger.debug('Allowing never-used credential {!r}'.format(cred))
            return False
        now = utc_now()
        delta = now - last_used
        logger.debug(f'Credential {cred.key} last used {delta.days} days ago')
        return delta.days >= int(365 * 1.5)

    def log_authn(self, user: IdPUser, success: Sequence[str], failure: Sequence[str]) -> None:
        """
        Log user authn success as well as failures.

        :param user: User
        :param success: List of successfully authenticated credentials
        :param failure: List of failed credentials
        """
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

    def __init__(self, uri: str, db_name: str = 'eduid_idp_authninfo', collection_name: str = 'authn_info'):
        logger.debug("Setting up AuthnInfoStoreMDB")
        self._db = MongoDB(db_uri=uri, db_name=db_name)
        self.collection = self._db.get_collection(collection_name)

    def credential_success(self, cred_ids: Sequence[str], ts: Optional[datetime] = None) -> None:
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
            self.collection.save({'_id': this, 'success_ts': ts})
        return None

    def update_user(
        self, user_id: ObjectId, success: Sequence[str], failure: Sequence[str], ts: Optional[datetime] = None
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
        self.collection.find_and_modify(
            query={'_id': user_id},
            update={
                '$set': {'success_ts': ts, 'last_credential_ids': success},
                '$inc': {f'fail_count.{this_month}': len(failure), f'success_count.{this_month}': len(success),},
            },
            upsert=True,
            new=True,
            multi=False,
        )
        return None

    def unlock_user(self, user_id: ObjectId, fail_count: int = 0, ts: Optional[datetime] = None) -> None:
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
        self.collection.find_and_modify(
            query={'_id': user_id},
            update={'$set': {f'fail_count.{this_month}': fail_count}},
            upsert=True,
            new=True,
            multi=False,
        )
        return None

    def get_user_authn_info(self, user: IdPUser) -> UserAuthnInfo:
        """ Load stored Authn information for user. """
        data = self.collection.find({'_id': user.user_id})
        if not data.count():
            return UserAuthnInfo(failures_this_month=0, last_used_credentials=[])
        return UserAuthnInfo.from_dict(data[0])

    def get_credential_last_used(self, cred_id: str) -> Optional[datetime]:
        """ Get the timestamp for when a specific credential was last used successfully.

        :return: Time of last successful use, or None
        """
        # Locate documents written by credential_success() above
        data = self.collection.find({'_id': cred_id})
        if not data.count():
            return None
        return data[0]['success_ts']


@dataclass(frozen=True)
class UserAuthnInfo:
    """
    Interpret data about a user loaded from the AuthnInfoStore.
    """

    failures_this_month: int
    last_used_credentials: List[str]

    @classmethod
    def from_dict(cls: Type[UserAuthnInfo], data: Dict[str, Any], ts: Optional[datetime] = None) -> UserAuthnInfo:
        """ Construct element from a data dict in database format. """
        data = dict(data)  # to not modify callers data

        if ts is None:
            ts = utc_now()
        this_month = (ts.year * 100) + ts.month  # format year-month as integer (e.g. 201402)

        _fail_count = data.get('fail_count', {})
        failures_this_month = _fail_count.get(str(this_month), 0)
        last_used_credentials = data.get('last_credential_ids', [])

        return cls(failures_this_month=failures_this_month, last_used_credentials=last_used_credentials)
