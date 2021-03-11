#
# Copyright (c) 2019 SUNET
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

"""
Code used in unit tests of various eduID applications.
"""

__author__ = 'leifj'

import logging
from copy import deepcopy
from typing import Optional

import bson
import pytest

from eduid.common.api.testing_base import WorkerTestCase
from eduid.userdb.exceptions import UserDoesNotExist
from eduid.userdb.proofing import ProofingUser
from eduid.workers.am.ams import AttributeFetcher
from eduid.workers.am.common import AmWorkerSingleton

logger = logging.getLogger(__name__)


USER_DATA = {
    'givenName': 'Testaren',
    'surname': 'Testsson',
    'displayName': 'John',
    'preferredLanguage': 'sv',
    'eduPersonPrincipalName': 'test-test',
    'mailAliases': [{'email': 'john@example.com', 'verified': True,}],
    'mobile': [{'verified': True, 'mobile': '+46700011336', 'primary': True}],
    'passwords': [
        {
            'credential_id': '112345678901234567890123',
            'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
        }
    ],
    'nins': [{'number': '123456781235', 'primary': True, 'verified': True}],
    'orcid': {
        'oidc_authz': {
            'token_type': 'bearer',
            'refresh_token': 'a_refresh_token',
            'access_token': 'an_access_token',
            'id_token': {
                'nonce': 'a_nonce',
                'sub': 'sub_id',
                'iss': 'https://issuer.example.org',
                'created_by': 'orcid',
                'exp': 1526890816,
                'auth_time': 1526890214,
                'iat': 1526890216,
                'aud': ['APP-YIAD0N1L4B3Z3W9Q'],
            },
            'expires_in': 631138518,
            'created_by': 'orcid',
        },
        'given_name': 'Testaren',
        'family_name': 'Testsson',
        'name': None,
        'id': 'orcid_unique_id',
        'verified': True,
        'created_by': 'orcid',
    },
}


class AMTestCase(WorkerTestCase):
    """ TestCase with an embedded Attribute Manager. """

    def tearDown(self):
        for fetcher in AmWorkerSingleton.af_registry.all_fetchers():
            fetcher.private_db._drop_whole_collection()
        super().tearDown()


class ProofingTestCase(AMTestCase):

    fetcher_name: Optional[str] = None
    fetcher: Optional[AttributeFetcher] = None

    def setUp(self, **kwargs):
        super().setUp(**kwargs)

        if self.fetcher_name:
            self.fetcher = AmWorkerSingleton.af_registry.get_fetcher(self.fetcher_name)

        self.user_data = deepcopy(USER_DATA)

        # Copy all user documents from the AM database into the private database used
        # by _all_ the fetchers available through self.af_registry.
        for userdoc in self.amdb._get_all_docs():
            proofing_user = ProofingUser.from_dict(userdoc)
            for fetcher in AmWorkerSingleton.af_registry.all_fetchers():
                fetcher.private_db.save(proofing_user, check_sync=False)

    def test_invalid_user(self):
        if self.fetcher is None:
            pytest.skip('Fetcher not initialised')

        with self.assertRaises(UserDoesNotExist):
            self.fetcher.fetch_attrs(bson.ObjectId('0' * 24))

    def test_malicious_attributes(self):
        if self.fetcher is None:
            pytest.skip('Fetcher not initialised')

        self.user_data.update({'malicious': 'hacker'})

        # Write bad entry into database
        result = self.fetcher.private_db._coll.insert_one(self.user_data)
        user_id = result.inserted_id

        with self.assertRaises(TypeError):
            self.fetcher.fetch_attrs(user_id)
