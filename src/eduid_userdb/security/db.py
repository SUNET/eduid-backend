# -*- coding: utf-8 -*-
#
# Copyright (c) 2017 NORDUnet A/S
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
from __future__ import absolute_import

import logging

from pymongo.errors import DuplicateKeyError

from eduid_userdb.db import BaseDB
from eduid_userdb.deprecation import deprecated
from eduid_userdb.exceptions import DocumentOutOfSync, MultipleDocumentsReturned
from eduid_userdb.security.state import PasswordResetEmailAndPhoneState, PasswordResetEmailState
from eduid_userdb.security.user import SecurityUser
from eduid_userdb.userdb import UserDB

logger = logging.getLogger(__name__)

__author__ = 'lundberg'


class SecurityUserDB(UserDB):

    UserClass = SecurityUser

    def __init__(self, db_uri, db_name='eduid_security', collection='profiles'):
        super(SecurityUserDB, self).__init__(db_uri, db_name, collection=collection)

    def save(self, user, check_sync=True, old_format=False):
        super(SecurityUserDB, self).save(user, check_sync=check_sync, old_format=old_format)


# @deprecated("Remove once the password reset views are served from their own webapp")
class PasswordResetStateDB(BaseDB):
    @deprecated("Remove once the password reset views are served from their own webapp")
    def __init__(self, db_uri, db_name='eduid_security', collection='password_reset_data'):
        super(PasswordResetStateDB, self).__init__(db_uri, db_name, collection=collection)

    def get_state_by_email_code(self, email_code, raise_on_missing=True):
        """
        Locate a state in the db given the state's email code.

        :param email_code: Code sent to the user
        :param raise_on_missing: Raise exception if True else return None

        :type email_code: six.string_types
        :type raise_on_missing: bool

        :return: PasswordResetState instance | None
        :rtype: PasswordResetState | None

        :raise self.DocumentDoesNotExist: No document match the search criteria
        :raise self.MultipleDocumentsReturned: More than one document matches the search criteria
        """
        spec = {'email_code.code': email_code}
        states = list(self._get_documents_by_filter(spec, raise_on_missing=raise_on_missing))

        if len(states) == 0:
            return None

        if len(states) > 1:
            raise MultipleDocumentsReturned("Multiple matching users for filter {!r}".format(filter))

        return self.init_state(states[0])

    def get_state_by_eppn(self, eppn, raise_on_missing=True):
        """
        Locate a state in the db given the users eppn.

        :param eppn: Users unique eppn
        :param raise_on_missing: Raise exception if True else return None

        :type eppn: six.string_types
        :type raise_on_missing: bool

        :return: PasswordResetState instance | None
        :rtype: PasswordResetState | None

        :raise self.DocumentDoesNotExist: No document match the search criteria
        :raise self.MultipleDocumentsReturned: More than one document matches the search criteria
        """
        state = self._get_document_by_attr('eduPersonPrincipalName', eppn, raise_on_missing)
        if state:
            return self.init_state(state)

    @staticmethod
    def init_state(state):
        if state.get('method') == 'email':
            return PasswordResetEmailState(data=state)
        if state.get('method') == 'email_and_phone':
            return PasswordResetEmailAndPhoneState(data=state)

    def save(self, state, check_sync=True):
        """

        :param state: PasswordResetState object
        :param check_sync: Ensure the document hasn't been updated in the database since it was loaded

        :type state: PasswordResetState
        :type check_sync: bool

        :return:
        """

        modified = state.modified_ts
        state.modified_ts = True  # update to current time
        if modified is None:
            # document has never been modified
            # Remove old reset password state
            old_state = self.get_state_by_eppn(state.eppn, raise_on_missing=False)
            if old_state:
                self.remove_state(old_state)

            result = self._coll.insert(state.to_dict())
            logging.debug("{!s} Inserted new state {!r} into {!r}): {!r})".format(self, state, self._coll_name, result))

        else:
            test_doc = {'eduPersonPrincipalName': state.eppn}
            if check_sync:
                test_doc['modified_ts'] = modified
            result = self._coll.update(test_doc, state.to_dict(), upsert=(not check_sync))
            if check_sync and result['n'] == 0:
                db_ts = None
                db_state = self._coll.find_one({'eppn': state.eppn})
                if db_state:
                    db_ts = db_state['modified_ts']
                logging.debug(
                    "{!s} FAILED Updating state {!r} (ts {!s}) in {!r}). "
                    "ts in db = {!s}".format(self, state, modified, self._coll_name, db_ts)
                )
                raise DocumentOutOfSync('Stale state object can\'t be saved')

            logging.debug(
                "{!s} Updated state {!r} (ts {!s}) in {!r}): {!r}".format(
                    self, state, modified, self._coll_name, result
                )
            )

    def remove_state(self, state):
        """
        :param state: ProofingStateClass object

        :type state: ProofingStateClass
        """
        self.remove_document({'eduPersonPrincipalName': state.eppn})
