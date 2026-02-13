from __future__ import annotations

import logging
import typing
import uuid
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any, NewType

from bson import ObjectId
from pydantic import BaseModel, ConfigDict, Field

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.element import ElementKey
from eduid.webapp.common.session import session
from eduid.webapp.idp.idp_authn import AuthnData
from eduid.webapp.idp.login_context import LoginContext

if typing.TYPE_CHECKING:
    from eduid.webapp.idp.sso_cache import SSOSessionCache

logger = logging.getLogger(__name__)

# A distinct type for session ids
SSOSessionId = NewType("SSOSessionId", str)


def create_session_id() -> SSOSessionId:
    """
    Create a unique value suitable for use as session identifier.

    The uniqueness and inability to guess is security critical!
    :return: session_id as bytes (to match what cookie decoding yields)
    """
    return SSOSessionId(str(uuid.uuid4()))


class SSOSession(BaseModel):
    """
    Single Sign On sessions are used to remember a previous authentication
    performed, to avoid re-authenticating users for every Service Provider
    they visit.

    The references to 'authn' here are strictly about what kind of Authn
    the user has performed. The resulting SAML AuthnContext is a product
    of this, as well as other policy decisions (such as what ID-proofing
    has taken place, what AuthnContext the SP requested and so on).

    :param authn_request_id: SAML request id of request that caused authentication
    :param authn_credentials: Data about what credentials were used to authn
    :param authn_timestamp: Authentication timestamp, in UTC

    # These fields are from the 'outer' scope of the session, and are
    # duplicated here for now. Can't be changed here, since they are removed in to_dict.

    :param created_ts: When the database document was created
    :param eppn: User eduPersonPrincipalName

    """

    eppn: str
    authn_credentials: list[AuthnData]
    authn_request_id: str = ""  # This should be obsolete now - used to be used to 'break' forceAuthn looping
    authn_timestamp: datetime = Field(default_factory=utc_now)  # TODO: probably obsolete
    created_ts: datetime = Field(default_factory=utc_now)
    expires_at: datetime = Field(default_factory=lambda: utc_now() + timedelta(minutes=5))
    obj_id: ObjectId = Field(default_factory=ObjectId, alias="_id")
    session_id: SSOSessionId = Field(default_factory=create_session_id)
    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)

    def __str__(self) -> str:
        # Session id allows impersonation if leaked, so only log a small part of it
        short_sessionid = self.session_id[:6] + "..."
        return (
            f"<{self.__class__.__name__}: _id={self.obj_id}, session_id={short_sessionid}, eppn={self.eppn}, "
            f"created={self.created_ts.isoformat()}, authn_ts={self.authn_timestamp.isoformat()}, "
            f"expires_at={self.expires_at.isoformat()}, age={self.age}>"
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the object in dict format (serialized for storing in MongoDB)."""
        res = self.model_dump()
        res["_id"] = res.pop("obj_id")
        return res

    @classmethod
    def from_dict(cls: type[SSOSession], data: Mapping[str, Any]) -> SSOSession:
        """Construct element from a data dict in database format."""
        return cls(**data)

    @property
    def public_id(self) -> str:
        """
        Return a identifier for this session that can't be used to hijack sessions
        if leaked through a log file etc.
        """
        return f"{self.eppn}.{self.created_ts.replace(microsecond=0).isoformat()}"

    @property
    def age(self) -> timedelta:
        """Return the age of this SSO session, in minutes."""
        return utc_now() - self.authn_timestamp

    def add_authn_credential(self, authn: AuthnData) -> None:
        """Add information about a credential successfully used in this session."""
        if not isinstance(authn, AuthnData):
            raise ValueError(f"data should be AuthnData (not {type(authn)})")

        # Store only the latest use of a particular credential.
        _creds: dict[ElementKey, AuthnData] = {x.cred_id: x for x in self.authn_credentials}
        _existing = _creds.get(authn.cred_id)
        # only replace if newer
        if not _existing or authn.timestamp > _existing.timestamp:
            _creds[authn.cred_id] = authn

        # sort on cred_id to have deterministic order in tests
        _list = list(_creds.values())
        self.authn_credentials = sorted(_list, key=lambda x: x.cred_id)


def record_authentication(
    ticket: LoginContext,
    eppn: str,
    sso_session: SSOSession | None,
    credentials: list[AuthnData],
    sso_session_lifetime: timedelta,
) -> SSOSession:
    if not sso_session:
        # Create new SSO session
        sso_session = SSOSession(authn_request_id=ticket.request_id, eppn=eppn, authn_credentials=[])

    if sso_session.eppn != eppn:
        raise RuntimeError(f"Not storing authn for user {eppn} in SSO session for user {sso_session.eppn}")

    for this in credentials:
        sso_session.add_authn_credential(this)

    # Advance the expiration of the session on each authentication
    sso_session.expires_at = utc_now() + sso_session_lifetime

    return sso_session


def get_sso_session() -> SSOSession | None:
    """
    Locate any existing SSO session for this request.

    :returns: SSO session if found (and valid)
    """
    # local import to avoid import-loop
    from eduid.webapp.idp.app import current_idp_app as current_app

    sso_session_lifetime = current_app.conf.sso_session_lifetime
    sso_sessions = current_app.sso_sessions

    sso_session = _lookup_sso_session(sso_sessions)
    if sso_session:
        logger.debug(f"SSO session found in the database: {sso_session}")
        _age = sso_session.age
        if _age > sso_session_lifetime:
            logger.debug(f"SSO session expired (age {_age} > {sso_session_lifetime})")
            return None
        logger.debug(f"SSO session is still valid (age {_age} <= {sso_session_lifetime})")
    return sso_session


def _lookup_sso_session(sso_sessions: SSOSessionCache) -> SSOSession | None:
    """
    See if a SSO session exists for this request, and return the data about
    the currently logged in user from the session store.

    :return: Data about currently logged in user
    """
    _sso = None

    _session_id = get_sso_session_id()
    if _session_id:
        _sso = sso_sessions.get_session(_session_id)
        logger.debug(f"Looked up SSO session using session ID {_session_id!r}: {_sso}")

    if not _sso:
        logger.debug("SSO session not found using IdP SSO cookie")

        if session.idp.sso_cookie_val is not None:
            # Debug issues with browsers not returning updated SSO cookie values.
            # Only log partial cookie value since it allows impersonation if leaked.
            _other_session_id = SSOSessionId(session.idp.sso_cookie_val)
            logger.debug(f"Found potential sso_cookie_val in the eduID session: ({session.idp.sso_cookie_val[:8]}...)")
            _other_sso = sso_sessions.get_session(_other_session_id)
            if _other_sso is not None:
                logger.info(f"Found no SSO session, but found one from session.idp.sso_cookie_val: {_other_sso}")

        if session.common.eppn:
            for this in sso_sessions.get_sessions_for_user(session.common.eppn):
                logger.info(f"Found no SSO session, but found SSO session for user {session.common.eppn}: {this}")

        return None
    logger.debug(f"Loaded SSO session {_sso}")
    return _sso


def get_sso_session_id() -> SSOSessionId | None:
    """
    Get the SSO session id from the IdP SSO cookie.

    :return: SSO session id
    """
    # local import to avoid import-loop
    from eduid.webapp.idp.app import current_idp_app as current_app
    from eduid.webapp.idp.mischttp import read_cookie

    _session_id = read_cookie(current_app.conf.sso_cookie.key)
    if not _session_id:
        return None
    logger.debug(f"Got SSO session ID from IdP SSO cookie {_session_id!r}")
    return SSOSessionId(_session_id)
