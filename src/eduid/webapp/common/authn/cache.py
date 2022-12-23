from typing import Any, Dict, Iterator, MutableMapping, TypeVar

from saml2.cache import Cache

from eduid.webapp.common.session.namespaces import AuthnRequestRef, PySAML2Dicts

VT = TypeVar("VT")


class SessionCacheAdapter(MutableMapping[str, VT]):

    key_prefix = "_saml2"

    def __init__(self, backend: PySAML2Dicts, key_suffix: str):
        self._backend = backend
        self._key = self.key_prefix + key_suffix
        if self._key not in self._backend:
            self._backend[self._key] = {}

    @property
    def key(self) -> str:
        return self._key

    @property
    def data(self) -> Dict[str, VT]:
        return self._backend[self._key]

    def __contains__(self, key: Any) -> bool:
        return key in self.data

    def __delitem__(self, key: str) -> None:
        del self.data[key]

    def __getitem__(self, key: str) -> VT:
        if key in self.data:
            return self.data[key]
        raise KeyError(key)

    def __len__(self) -> int:
        return len(self.data)

    def __iter__(self) -> Iterator[str]:
        return iter(self.data)

    def __setitem__(self, key: str, value: VT) -> None:
        self.data[key] = value


class OutstandingQueriesCache(object):
    """Handles the queries that have been sent to the IdP and have not been replied yet."""

    def __init__(self, backend: PySAML2Dicts):
        self._db = SessionCacheAdapter[AuthnRequestRef](backend, "_outstanding_queries")

    def outstanding_queries(self) -> Dict[str, AuthnRequestRef]:
        return dict(self._db.items() or {})

    def set(self, saml2_session_id: str, came_from: AuthnRequestRef) -> None:
        self._db[saml2_session_id] = came_from

    def delete(self, saml2_session_id: str) -> None:
        if saml2_session_id in self._db:
            del self._db[saml2_session_id]


class IdentityCache(Cache):
    """Handles information about the users that have been successfully logged in.

    This information is useful because when the user logs out we must
    know where does he come from in order to notify such IdP/AA.
    """

    def __init__(self, backend: PySAML2Dicts):
        self._db = SessionCacheAdapter[Any](backend, "_identities")
        self._sync = False


class StateCache(SessionCacheAdapter[Any]):
    """Store state information that is needed to associate a logout request with its response."""

    def __init__(self, backend: PySAML2Dicts):
        super().__init__(backend, "_state")
