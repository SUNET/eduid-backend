# -*- coding: utf-8 -*-
#
# Copyright (c) 2015 NORDUnet A/S
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

from bson import ObjectId
from bson.errors import InvalidId

from eduid_userdb.db import BaseDB
from eduid_userdb.userdb import UserDB
from eduid_userdb.exceptions import DocumentOutOfSync
from eduid_userdb.proofing import LetterProofingState, OidcProofingState
from eduid_userdb.proofing import EmailProofingState, ProofingUser
from eduid_userdb.proofing import PhoneProofingState
from eduid_userdb.exceptions import MultipleDocumentsReturned

import logging
logger = logging.getLogger(__name__)

__author__ = 'lundberg'


class ProofingStateDB(BaseDB):

    ProofingStateClass = None

    def __init__(self, db_uri, db_name, collection='proofing_data'):
        BaseDB.__init__(self, db_uri, db_name, collection)

    # XXX: Deprecated function that will be removed
    def get_state_by_user_id(self, user_id, eppn, raise_on_missing=True):
        """
        Locate a state in the db given the state's user_id.

        :param user_id: User identifier
        :param eppn: eduPersonPrincipalName
        :param raise_on_missing: Raise exception if True else return None

        :type user_id: bson.ObjectId | str | unicode
        :type eppn: str | unicode
        :type raise_on_missing: bool

        :return: ProofingStateClass instance | None
        :rtype: ProofingStateClass | None

        :raise self.DocumentDoesNotExist: No user match the search criteria
        :raise self.MultipleDocumentsReturned: More than one user matches the search criteria
        """
        if not isinstance(user_id, ObjectId):
            try:
                user_id = ObjectId(user_id)
            except InvalidId:
                return None
        doc = self._get_document_by_attr('user_id', user_id, raise_on_missing)
        if doc:
            # Rewrite state document with eppn instead of user_id
            doc['eduPersonPrincipalName'] = eppn  # Add eppn to data as it was missing
            user_id = doc.pop('user_id')
            proofing_state = self.ProofingStateClass(doc)
            logger.info('Rewriting user_id proofing state to eppn proofing state')
            logger.debug('Proofing state user_id: {!s}'.format(user_id))
            logger.debug('Proofing state eppn: {!s}'.format(eppn))
            self.remove_document({'user_id': user_id})
            logger.info('Removed user_id proofing state')

            # The old document is removed and therefore no sync check is needed
            self.save(proofing_state, check_sync=False)
            logger.info('Saved eppn proofing state')
            return self.get_state_by_eppn(eppn, raise_on_missing)

    def get_state_by_eppn(self, eppn, raise_on_missing=True):
        """
        Locate a state in the db given the state user's eppn.

        :param eppn: eduPersonPrincipalName
        :param raise_on_missing: Raise exception if True else return None

        :type eppn: str | unicode
        :type raise_on_missing: bool

        :return: ProofingStateClass instance | None
        :rtype: ProofingStateClass | None

        :raise self.DocumentDoesNotExist: No user match the search criteria
        :raise self.MultipleDocumentsReturned: More than one user matches the search criteria
        """

        state = self._get_document_by_attr('eduPersonPrincipalName', eppn, raise_on_missing)
        if state:
            return self.ProofingStateClass(state)

    def save(self, state, check_sync=True):
        """

        :param state: ProofingStateClass object
        :param check_sync: Ensure the document hasn't been updated in the database since it was loaded

        :type state: ProofingStateClass
        :type check_sync: bool

        :return:
        """

        modified = state.modified_ts
        state.modified_ts = True  # update to current time
        if modified is None:
            # document has never been modified
            result = self._coll.insert(state.to_dict())
            logging.debug("{!s} Inserted new state {!r} into {!r}): {!r})".format(
                self, state, self._coll_name, result))
        else:
            test_doc = {'eduPersonPrincipalName': state.eppn}
            if check_sync:
                test_doc['modified_ts'] = modified
            result = self._coll.update(test_doc, state.to_dict(), upsert=(not check_sync))
            if check_sync and result['n'] == 0:
                db_ts = None
                db_state = self._coll.find_one({'eduPersonPrincipalName': state.eppn})
                if db_state:
                    db_ts = db_state['modified_ts']
                logging.debug("{!s} FAILED Updating state {!r} (ts {!s}) in {!r}). "
                              "ts in db = {!s}".format(self, state, modified, self._coll_name, db_ts))
                raise DocumentOutOfSync('Stale state object can\'t be saved')

            logging.debug("{!s} Updated state {!r} (ts {!s}) in {!r}): {!r}".format(
                self, state, modified, self._coll_name, result))

    def remove_state(self, state):
        """
        :param state: ProofingStateClass object

        :type state: ProofingStateClass
        """
        self.remove_document({'eduPersonPrincipalName': state.eppn})


class LetterProofingStateDB(ProofingStateDB):

    ProofingStateClass = LetterProofingState

    def __init__(self, db_uri, db_name='eduid_idproofing_letter'):
        ProofingStateDB.__init__(self, db_uri, db_name)


class EmailProofingStateDB(ProofingStateDB):

    ProofingStateClass = EmailProofingState

    def __init__(self, db_uri, db_name='eduid_emails'):
        ProofingStateDB.__init__(self, db_uri, db_name)

    def get_state_by_eppn_and_code(self, eppn, code, raise_on_missing=True):
        """
        Locate a state in the db given the verification code.

        :param code: verification code
        :param raise_on_missing: Raise exception if True else return None

        :type code: str | unicode
        :type raise_on_missing: bool

        :return: ProofingStateClass instance | None
        :rtype: ProofingStateClass | None

        :raise self.DocumentDoesNotExist: No user match the search criteria
        :raise self.MultipleDocumentsReturned: More than one user
                                               matches the search criteria
        """
        spec = {'eduPersonPrincipalName': eppn,
                'verification': {'verification_code': code}}
        verifications = self._get_documents_by_filter(spec,
                raise_on_missing=raise_on_missing)

        if verifications.count() > 1:
            raise MultipleDocumentsReturned("Multiple matching"
                    " documents for {!r}".format(spec))

        return self.ProofingStateClass(verification[0])


class PhoneProofingStateDB(EmailProofingStateDB):

    ProofingStateClass = PhoneProofingState

    def __init__(self, db_uri, db_name='eduid_phones'):
        ProofingStateDB.__init__(self, db_uri, db_name)

    def get_state_by_mail_and_code(self, mail, code, raise_on_missing=True):
        """
        Locate a state in the db given the verification code.

        :param code: verification code
        :param raise_on_missing: Raise exception if True else return None

        :type code: str | unicode
        :type raise_on_missing: bool

        :return: ProofingStateClass instance | None
        :rtype: ProofingStateClass | None

        :raise self.DocumentDoesNotExist: No user match the search criteria
        :raise self.MultipleDocumentsReturned: More than one user
                                               matches the search criteria
        """
        spec = {'$or': [
            {'mail': email},
            {'mailAliases': {'$elemMatch': {'email': email}}}
          ],
          'verification': {'verification_code': code}}

        verifications = self._get_documents_by_filter(spec,
                raise_on_missing=raise_on_missing)

        if verifications.count() > 1:
            raise MultipleDocumentsReturned("Multiple matching"
                    " documents for {!r}".format(spec))

        return self.ProofingStateClass(verification[0])


class OidcProofingStateDB(ProofingStateDB):

    ProofingStateClass = OidcProofingState

    def __init__(self, db_uri, db_name='eduid_oidc_proofing'):
        ProofingStateDB.__init__(self, db_uri, db_name)

    def get_state_by_oidc_state(self, oidc_state, raise_on_missing=True):
        """
        Locate a state in the db given the user's OIDC state.

        :param oidc_state: OIDC state param
        :param raise_on_missing: Raise exception if True else return None

        :type oidc_state: str | unicode
        :type raise_on_missing: bool

        :return: ProofingStateClass instance | None
        :rtype: ProofingStateClass | None

        :raise self.DocumentDoesNotExist: No user match the search criteria
        :raise self.MultipleDocumentsReturned: More than one user matches the search criteria
        """

        state = self._get_document_by_attr('state', oidc_state, raise_on_missing)
        if state:
            return self.ProofingStateClass(state)


class ProofingUserDB(UserDB):

    UserClass = ProofingUser

    def __init__(self, db_uri, db_name, collection='profiles'):
        super(ProofingUserDB, self).__init__(db_uri, db_name, collection=collection)

    def save(self, user, check_sync=True, old_format=True):
        # XXX old_format default is set to True here
        super(ProofingUserDB, self).save(user, check_sync=check_sync, old_format=old_format)


class LetterProofingUserDB(ProofingUserDB):

    def __init__(self, db_uri, db_name='eduid_idproofing_letter'):
        ProofingUserDB.__init__(self, db_uri, db_name)


class OidcProofingUserDB(ProofingUserDB):

    def __init__(self, db_uri, db_name='eduid_oidc_proofing'):
        ProofingUserDB.__init__(self, db_uri, db_name)
