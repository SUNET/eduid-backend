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
import datetime
import logging
from operator import itemgetter
from typing import Optional, Type, TypeVar

from eduid.userdb.db import BaseDB
from eduid.userdb.exceptions import DocumentOutOfSync
from eduid.userdb.proofing.state import (
    EmailProofingState,
    LetterProofingState,
    OidcProofingState,
    OrcidProofingState,
    PhoneProofingState,
    ProofingState,
)
from eduid.userdb.proofing.user import ProofingUser
from eduid.userdb.userdb import UserDB

logger = logging.getLogger(__name__)

__author__ = 'lundberg'

ProofingStateInstance = TypeVar('ProofingStateInstance', bound=ProofingState)


class ProofingStateDB(BaseDB):

    ProofingStateClass: Type[ProofingState] = ProofingState

    def __init__(self, db_uri: str, db_name: str, collection='proofing_data'):
        super().__init__(db_uri, db_name, collection)

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
            return self.ProofingStateClass.from_dict(state)

    def get_latest_state_by_spec(self, spec: dict, raise_on_missing: bool = True) -> Optional[ProofingStateInstance]:
        """
        Returns the latest inserted state and __removes any other state found__ defined by the spec .

        :param spec: the search filter
        :param raise_on_missing: Raise exception if True else return None
        :return: Latest state found
        """
        docs = self._get_documents_by_filter(spec, raise_on_missing=raise_on_missing)
        if not docs:
            return None

        if len(docs) > 1:
            # Ex. multiple states for same user and email address matched
            # This should not be possible but we have seen it happen
            states = sorted(docs, key=itemgetter('modified_ts'))
            state_to_keep = states.pop(-1)  # Keep latest state
            for state in states:
                self.remove_document(state['_id'])
            return self.ProofingStateClass.from_dict(state_to_keep)

        return self.ProofingStateClass.from_dict(docs[0])

    def save(self, state, check_sync=True):
        """
        :param state: ProofingStateClass object
        :param check_sync: Ensure the document hasn't been updated in the database since it was loaded

        :type state: ProofingStateClass
        :type check_sync: bool

        :return:
        """
        modified = state.modified_ts
        state.modified_ts = datetime.datetime.utcnow()  # update to current time
        if modified is None:
            # document has never been modified
            result = self._coll.insert_one(state.to_dict())
            logging.debug(f"{self} Inserted new state {state} into {self._coll_name}): {result.inserted_id})")
        else:
            test_doc = {'eduPersonPrincipalName': state.eppn}
            if check_sync:
                test_doc['modified_ts'] = modified
            result = self._coll.replace_one(test_doc, state.to_dict(), upsert=(not check_sync))
            if check_sync and result.matched_count == 0:
                db_ts = None
                db_state = self._coll.find_one({'eduPersonPrincipalName': state.eppn})
                if db_state:
                    db_ts = db_state['modified_ts']
                logging.error(
                    f'{self} FAILED Updating state {state} (ts {modified}) in {self._coll_name}). ts in db = {db_ts!s}'
                )
                raise DocumentOutOfSync('Stale state object can\'t be saved')

            logging.debug(
                "{!s} Updated state {} (ts {}) in {}): {}".format(self, state, modified, self._coll_name, result)
            )

    def remove_state(self, state):
        """
        :param state: ProofingStateClass object

        :type state: ProofingStateClass
        """
        self.remove_document({'eduPersonPrincipalName': state.eppn})


class LetterProofingStateDB(ProofingStateDB):
    ProofingStateClass = LetterProofingState

    def __init__(self, db_uri: str, db_name: str = 'eduid_idproofing_letter'):
        super().__init__(db_uri, db_name)


class EmailProofingStateDB(ProofingStateDB):
    ProofingStateClass = EmailProofingState

    def __init__(self, db_uri: str, db_name: str = 'eduid_email'):
        super().__init__(db_uri, db_name)

    def get_state_by_eppn_and_email(
        self, eppn: str, email: str, raise_on_missing: bool = True
    ) -> Optional[EmailProofingState]:
        """
        Locate a state in the db given the eppn of the user and the
        email to be verified.

        :raise self.DocumentDoesNotExist: No user match the search criteria
        :raise self.MultipleDocumentsReturned: More than one user
                                               matches the search criteria
        """
        spec = {'eduPersonPrincipalName': eppn, 'verification.email': email}
        return self.get_latest_state_by_spec(spec, raise_on_missing)

    def remove_state(self, state):
        """
        :param state: ProofingStateClass object

        :type state: ProofingStateClass
        """
        self.remove_document({'eduPersonPrincipalName': state.eppn, 'verification.email': state.verification.email})


class PhoneProofingStateDB(ProofingStateDB):
    ProofingStateClass = PhoneProofingState

    def __init__(self, db_uri: str, db_name: str = 'eduid_phone'):
        ProofingStateDB.__init__(self, db_uri, db_name)

    def get_state_by_eppn_and_mobile(self, eppn, number, raise_on_missing=True):
        """
        Locate a state in the db given the eppn of the user and the
        mobile to be verified.

        :param number: mobile to verify
        :param raise_on_missing: Raise exception if True else return None

        :type number: str | unicode
        :type raise_on_missing: bool

        :return: ProofingStateClass instance | None
        :rtype: ProofingStateClass | None

        :raise self.DocumentDoesNotExist: No user match the search criteria
        :raise self.MultipleDocumentsReturned: More than one user
                                               matches the search criteria
        """
        spec = {'eduPersonPrincipalName': eppn, 'verification.number': number}
        return self.get_latest_state_by_spec(spec, raise_on_missing)

    def remove_state(self, state):
        """
        :param state: ProofingStateClass object

        :type state: ProofingStateClass
        """
        self.remove_document({'eduPersonPrincipalName': state.eppn, 'verification.number': state.verification.number})


class OidcStateDB(ProofingStateDB):
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
            return self.ProofingStateClass.from_dict(state)


class OidcProofingStateDB(OidcStateDB):
    ProofingStateClass = OidcProofingState

    def __init__(self, db_uri: str, db_name: str = 'eduid_oidc_proofing'):
        super().__init__(db_uri, db_name)


class OrcidProofingStateDB(OidcStateDB):
    ProofingStateClass = OrcidProofingState

    def __init__(self, db_uri: str, db_name: str = 'eduid_orcid'):
        super().__init__(db_uri, db_name)


class ProofingUserDB(UserDB):
    UserClass = ProofingUser

    def __init__(self, db_uri: str, db_name: str, collection: str = 'profiles'):
        super().__init__(db_uri, db_name, collection=collection)

    def save(self, user, check_sync=True):
        super().save(user, check_sync=check_sync)


class LetterProofingUserDB(ProofingUserDB):
    def __init__(self, db_uri: str, db_name: str = 'eduid_idproofing_letter'):
        super().__init__(db_uri, db_name)


class OidcProofingUserDB(ProofingUserDB):
    def __init__(self, db_uri: str, db_name: str = 'eduid_oidc_proofing'):
        super().__init__(db_uri, db_name)


class PhoneProofingUserDB(ProofingUserDB):
    def __init__(self, db_uri: str, db_name: str = 'eduid_phone'):
        super().__init__(db_uri, db_name)


class EmailProofingUserDB(ProofingUserDB):
    def __init__(self, db_uri: str, db_name: str = 'eduid_email'):
        super().__init__(db_uri, db_name)


class LookupMobileProofingUserDB(ProofingUserDB):
    def __init__(self, db_uri: str, db_name: str = 'eduid_lookup_mobile_proofing'):
        super().__init__(db_uri, db_name)


class OrcidProofingUserDB(ProofingUserDB):
    def __init__(self, db_uri: str, db_name: str = 'eduid_orcid'):
        super().__init__(db_uri, db_name)


class EidasProofingUserDB(ProofingUserDB):
    def __init__(self, db_uri: str, db_name: str = 'eduid_eidas'):
        super().__init__(db_uri, db_name)
