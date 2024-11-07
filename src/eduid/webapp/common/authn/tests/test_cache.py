import unittest

from eduid.webapp.common.authn.cache import IdentityCache, OutstandingQueriesCache, SessionCacheAdapter
from eduid.webapp.common.session.namespaces import AuthnRequestRef, PySAML2Dicts


class SessionCacheAdapterTests(unittest.TestCase):
    def test_init(self) -> None:
        backend = PySAML2Dicts({"unrelated": {"foo": "bar"}})
        psca = SessionCacheAdapter[str](backend, "saml2")

        assert psca._backend == backend
        assert psca.key == psca.key_prefix + "saml2"

    def test_get_objects(self) -> None:
        backend = PySAML2Dicts({"unrelated": {"foo": "bar"}})
        psca = SessionCacheAdapter[str](backend, "saml2")

        assert dict(psca.items()) == {}

    def test_set_objects(self) -> None:
        backend = PySAML2Dicts({"unrelated": {"foo": "bar"}})
        psca = SessionCacheAdapter[str](backend, "saml2")

        psca.update({"onekey": "onevalue"})

        assert dict(psca.items()) == {"onekey": "onevalue"}

    def test_sync(self) -> None:
        backend = PySAML2Dicts({"unrelated": {"foo": "bar"}})
        psca = SessionCacheAdapter[str](backend, "saml2")

        assert dict(psca.items()) == {}

        psca["onekey"] = "onevalue"

        assert dict(psca.items()) == {"onekey": "onevalue"}
        assert psca["onekey"] == "onevalue"


class OutstandingQueriesCacheTests(unittest.TestCase):
    def test_init(self) -> None:
        fake_session_dict = PySAML2Dicts(
            {
                "user": {
                    "mail": "someone@example.com",
                }
            }
        )
        oqc = OutstandingQueriesCache(fake_session_dict)

        self.assertIsInstance(oqc._db, SessionCacheAdapter)

    def test_outstanding_queries(self) -> None:
        oqc = OutstandingQueriesCache(PySAML2Dicts({}))
        oqc._db["user"] = AuthnRequestRef("someone@example.com")

        assert oqc.outstanding_queries() == {"user": "someone@example.com"}

    def test_set(self) -> None:
        oqc = OutstandingQueriesCache(PySAML2Dicts({}))
        oqc.set("session_id", AuthnRequestRef("/next"))

        assert oqc.outstanding_queries() == {"session_id": "/next"}

    def test_delete(self) -> None:
        oqc = OutstandingQueriesCache(PySAML2Dicts({}))
        oqc.set("session_id", AuthnRequestRef("/next"))
        assert oqc.outstanding_queries() == {"session_id": "/next"}

        oqc.delete("session_id")

        assert oqc.outstanding_queries() == {}


class IdentityCacheTests(unittest.TestCase):
    def test_init(self) -> None:
        ic = IdentityCache(PySAML2Dicts({}))

        assert isinstance(ic._db, SessionCacheAdapter)
        assert not ic._sync
