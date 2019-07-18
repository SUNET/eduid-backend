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

import datetime

from eduid_common.idp.user import IdPUser
from eduid_userdb import MongoDB
from eduid_userdb.exceptions import UserHasNotCompletedSignup


class AuthnData(object):
    """
    Data about a successful authentication.

    Returned from functions performing authentication.
    """
    def __init__(self, user, credential, timestamp):
        self.user = user
        self.credential = credential
        self.timestamp = timestamp

    @property
    def user(self):
        """
        :rtype: IdPUser
        """
        return self._user

    @user.setter
    def user(self, value):
        """
        :type value: IdPUser
        """
        if not isinstance(value, IdPUser):
            raise ValueError('Invalid user (expect IdPUser, got {})'.format(type(value)))
        self._user = value

    @property
    def credential(self):
        """
        :rtype: Password | U2F
        """
        return self._credential

    @credential.setter
    def credential(self, value):
        """
        :type value: Password | U2F
        """
        # isinstance is broken here with Python2:
        #   ValueError: Invalid/unknown credential (got <class 'eduid_userdb.u2f.U2F'>)
        #if not isinstance(value, Password) or isinstance(value, U2F):
        if not hasattr(value, 'key'):
            raise ValueError('Invalid/unknown credential (got {})'.format(type(value)))
        self._credential = value

    @property
    def timestamp(self):
        """
        :rtype: datetime.datetime
        """
        return self._timestamp

    @timestamp.setter
    def timestamp(self, value):
        """
        :type value: datetime.datetime
        """
        if not isinstance(value, datetime.datetime):
            raise ValueError('Invalid timestamp (expect datetime, got {})'.format(type(value)))
        self._timestamp = value.replace(tzinfo = None)  # thanks for not having timezone.utc, Python2

    def to_session_dict(self):
        return {'cred_id': self.credential.key,
                'authn_ts': self.timestamp,
                }


class AuthnInfoStore(object):
    """
    Abstract AuthnInfoStore.
    """
    def __init__(self, logger):
        self.logger = logger


class AuthnInfoStoreMDB(AuthnInfoStore):
    """
    This is a MongoDB version of AuthnInfoStore().
    """

    def __init__(self, uri, logger, db_name = 'eduid_idp_authninfo',
                 collection_name = 'authn_info',
                 **kwargs):
        AuthnInfoStore.__init__(self, logger)

        logger.debug("Setting up AuthnInfoStoreMDB")
        self._db = MongoDB(db_uri = uri, db_name = db_name)
        self.collection = self._db.get_collection(collection_name)

    def credential_success(self, cred_ids, ts=None):
        """
        Kantara AL2_CM_CSM#050 requires that any credential that is not used for
        a period of 18 months is disabled (taken to mean revoked).

        Therefor we need to log all successful authentications and have a cron
        job handling the revoking of unused credentials.

        :param cred_ids: List of Credential ID
        :param ts: Optional timestamp
        :return: None

        :type ts: datetime.datetime()
        :type cred_ids: [bson.ObjectId]
        """
        if ts is None:
            ts = datetime.datetime.utcnow()
        # Update all existing entrys in one go would've been nice, but pymongo does not
        # return meaningful data for multi=True, so it is not possible to figure out
        # which entrys were actually updated :(
        for this in cred_ids:
            self.collection.save(
                {
                    '_id': this,
                    'success_ts': ts,
                },
            )
        return None

    def update_user(self, user_id, success, failure, ts=None):
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
        :return: None

        :type user_id: bson.ObjectId
        :type success: [bson.ObjectId]
        :type failure: [bson.ObjectId]
        :type ts: datetime.datetime() | None
        """
        if ts is None:
            ts = datetime.datetime.utcnow()
        this_month = (ts.year * 100) + ts.month  # format year-month as integer (e.g. 201402)
        self.collection.find_and_modify(
            query = {
                '_id': user_id,
            }, update = {
                '$set': {
                    'success_ts': ts,
                    'last_credential_ids': success,
                },
                '$inc': {
                    'fail_count.' + str(this_month): len(failure),
                    'success_count.' + str(this_month): len(success)
                },
            }, upsert = True, new = True, multi = False)
        return None

    def unlock_user(self, user_id, fail_count = 0, ts=None):
        """
        Set the fail count for a specific user and month.

        Used from the CLI `unlock_user`.

        :param user_id: User identifier
        :param fail_count: Number of failed attempts to put the user at
        :param ts: Optional timestamp

        :type user_id: bson.ObjectId
        :type fail_count: int
        :type ts: datetime.datetime() | None

        :return: None
        """
        if ts is None:
            ts = datetime.datetime.utcnow()
        this_month = (ts.year * 100) + ts.month  # format year-month as integer (e.g. 201402)
        self.collection.find_and_modify(
            query = {
                '_id': user_id,
            }, update = {
                '$set': {
                    'fail_count.' + str(this_month): fail_count,
                },
            }, upsert = True, new = True, multi = False)
        return None

    def get_user_authn_info(self, user):
        """
        Load stored Authn information for user.

        :param user: User object

        :type user: IdPUser
        :rtype: UserAuthnInfo
        """
        data = self.collection.find({'_id': user.user_id})
        if not data.count():
            return UserAuthnInfo({})
        return UserAuthnInfo(data[0])

    def get_credential_last_used(self, cred_id):
        """
        Get the timestamp for when a specific credential was last used successfully.

        :param cred_id: Id of credential
        :type cred_id: bson.ObjectId

        :return: None | datetime.datetime
        """
        # Locate documents written by credential_success() above
        data = self.collection.find({'_id': cred_id})
        if not data.count():
            return None
        return data[0]['success_ts']


class UserAuthnInfo(object):
    """
    Interpret data loaded from the AuthnInfoStore.
    """

    def __init__(self, data):
        self._data = data

    def failures_this_month(self, ts=None):
        """
        Return the number of failed login attempts for a user in a certain month.

        :param ts: Optional timestamp

        :return: Number of failed attempts

        :type ts: datetime.datetime | None
        :rtype: int
        """
        if ts is None:
            ts = datetime.datetime.utcnow()
        this_month = (ts.year * 100) + ts.month  # format year-month as integer (e.g. 201402)
        return self._data.get('fail_count', {}).get(str(this_month), 0)

    def last_used_credentials(self):
        """
        Get the credential IDs used in the last successful authentication for this user.

        :return: List of IDs

        :rtype: [bson.ObjectId]
        """
        return self._data.get('last_credential_ids', [])
