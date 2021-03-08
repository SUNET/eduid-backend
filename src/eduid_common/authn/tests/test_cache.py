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
import unittest

from eduid_common.authn.cache import IdentityCache, OutstandingQueriesCache, SessionCacheAdapter


class SessionCacheAdapterTests(unittest.TestCase):
    def test_init(self):
        fake_session_dict = {
            'user': 'someone@example.com',
        }
        psca = SessionCacheAdapter(fake_session_dict, 'saml2')

        self.assertEqual(psca.session, fake_session_dict)
        self.assertEqual(psca.key, psca.key_prefix + 'saml2')

    def test_get_objects(self):
        fake_session_dict = {
            'user': 'someone@example.com',
        }
        psca = SessionCacheAdapter(fake_session_dict, 'saml2')

        self.assertEqual(psca._get_objects(), {})

    def test_set_objects(self):
        fake_session_dict = {
            'user': 'someone@example.com',
        }
        psca = SessionCacheAdapter(fake_session_dict, 'saml2')

        psca._set_objects(
            {'onekey': 'onevalue',}
        )

        self.assertEqual(psca._get_objects(), {'onekey': 'onevalue'})

    def test_sync(self):
        fake_session_dict = {
            'user': 'someone@example.com',
        }
        psca = SessionCacheAdapter(fake_session_dict, 'saml2')

        psca.sync()
        self.assertEqual(psca._get_objects(), {})

        psca['onekey'] = 'onevalue'

        psca.sync()
        self.assertEqual(psca._get_objects(), {'onekey': 'onevalue'})


class OutstandingQueriesCacheTests(unittest.TestCase):
    def test_init(self):
        fake_session_dict = {
            'user': 'someone@example.com',
        }
        oqc = OutstandingQueriesCache(fake_session_dict)

        self.assertIsInstance(oqc._db, SessionCacheAdapter)

    def test_outstanding_queries(self):

        oqc = OutstandingQueriesCache({})
        oqc._db['user'] = 'someone@example.com'
        oqc._db.sync()

        self.assertEqual(oqc.outstanding_queries(), {'user': 'someone@example.com'})

    def test_set(self):
        oqc = OutstandingQueriesCache({})
        oqc.set('session_id', '/next')

        self.assertEqual(oqc.outstanding_queries(), {'session_id': '/next'})

    def test_delete(self):
        oqc = OutstandingQueriesCache({})
        oqc.set('session_id', '/next')
        self.assertEqual(oqc.outstanding_queries(), {'session_id': '/next'})

        oqc.delete('session_id')

        self.assertEqual(oqc.outstanding_queries(), {})


class IdentityCacheTests(unittest.TestCase):
    def test_init(self):
        ic = IdentityCache({})

        self.assertIsInstance(ic._db, SessionCacheAdapter)
        self.assertTrue(ic._sync, True)
