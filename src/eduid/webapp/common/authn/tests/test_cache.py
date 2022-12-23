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

from eduid.webapp.common.authn.cache import IdentityCache, OutstandingQueriesCache, SessionCacheAdapter
from eduid.webapp.common.session.namespaces import AuthnRequestRef, PySAML2Dicts


class SessionCacheAdapterTests(unittest.TestCase):
    def test_init(self):
        backend = PySAML2Dicts({"unrelated": {"foo": "bar"}})
        psca = SessionCacheAdapter[str](backend, "saml2")

        assert psca._backend == backend
        assert psca.key == psca.key_prefix + "saml2"

    def test_get_objects(self):
        backend = PySAML2Dicts({"unrelated": {"foo": "bar"}})
        psca = SessionCacheAdapter[str](backend, "saml2")

        assert dict(psca.items()) == {}

    def test_set_objects(self):
        backend = PySAML2Dicts({"unrelated": {"foo": "bar"}})
        psca = SessionCacheAdapter[str](backend, "saml2")

        psca.update({"onekey": "onevalue"})

        assert dict(psca.items()) == {"onekey": "onevalue"}

    def test_sync(self):
        backend = PySAML2Dicts({"unrelated": {"foo": "bar"}})
        psca = SessionCacheAdapter[str](backend, "saml2")

        assert dict(psca.items()) == {}

        psca["onekey"] = "onevalue"

        assert dict(psca.items()) == {"onekey": "onevalue"}
        assert psca["onekey"] == "onevalue"


class OutstandingQueriesCacheTests(unittest.TestCase):
    def test_init(self):
        fake_session_dict = {
            "user": "someone@example.com",
        }
        oqc = OutstandingQueriesCache(fake_session_dict)

        self.assertIsInstance(oqc._db, SessionCacheAdapter)

    def test_outstanding_queries(self):

        oqc = OutstandingQueriesCache(PySAML2Dicts({}))
        oqc._db["user"] = AuthnRequestRef("someone@example.com")

        assert oqc.outstanding_queries() == {"user": "someone@example.com"}

    def test_set(self):
        oqc = OutstandingQueriesCache(PySAML2Dicts({}))
        oqc.set("session_id", AuthnRequestRef("/next"))

        assert oqc.outstanding_queries() == {"session_id": "/next"}

    def test_delete(self):
        oqc = OutstandingQueriesCache(PySAML2Dicts({}))
        oqc.set("session_id", AuthnRequestRef("/next"))
        assert oqc.outstanding_queries() == {"session_id": "/next"}

        oqc.delete("session_id")

        assert oqc.outstanding_queries() == {}


class IdentityCacheTests(unittest.TestCase):
    def test_init(self):
        ic = IdentityCache(PySAML2Dicts({}))

        assert isinstance(ic._db, SessionCacheAdapter)
        assert ic._sync == False
