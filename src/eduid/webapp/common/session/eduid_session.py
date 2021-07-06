from __future__ import annotations

import json
import logging
import os
import pprint
from collections.abc import MutableMapping
from time import time
from typing import TYPE_CHECKING, Any, Optional

from flask import Request as FlaskRequest
from flask import Response as FlaskResponse
from flask.sessions import SessionInterface, SessionMixin
from pydantic import BaseModel

from eduid.common.config.base import EduIDBaseAppConfig
from eduid.common.config.exceptions import BadConfiguration
from eduid.common.misc.timeutil import utc_now
from eduid.webapp.common.session.meta import SessionMeta
from eduid.webapp.common.session.namespaces import (
    Actions,
    Authn_Namespace,
    Common,
    Eidas_Namespace,
    IdP_Namespace,
    MfaAction,
    ResetPasswordNS,
    SecurityNS,
    Signup,
    TimestampedNS,
)
from eduid.webapp.common.session.redis_session import (
    EduidJSONEncoder,
    RedisEncryptedSession,
    SessionManager,
    SessionOutOfSync,
)

if TYPE_CHECKING:
    # From https://stackoverflow.com/a/39757388
    # The TYPE_CHECKING constant is always False at runtime, so the import won't be evaluated, but mypy
    # (and other type-checking tools) will evaluate the contents of this block.
    from eduid.webapp.common.api.app import EduIDBaseApp

    # keep pycharm from optimising away the above import
    assert EduIDBaseApp

logger = logging.getLogger(__name__)


class EduidNamespaces(BaseModel):
    common: Optional[Common] = None
    mfa_action: Optional[MfaAction] = None
    signup: Optional[Signup] = None
    actions: Optional[Actions] = None
    reset_password: Optional[ResetPasswordNS] = None
    security: Optional[SecurityNS] = None
    idp: Optional[IdP_Namespace] = None
    eidas: Optional[Eidas_Namespace] = None
    authn: Optional[Authn_Namespace] = None


class EduidSession(SessionMixin, MutableMapping):
    """
    Session implementing the flask.sessions.SessionMixin interface.

    What Flask gives us:

      - a dict-like session object, within a framework that will persist the session on changes etc.

    What Flask does not give us:

      - typed (and validated) information in sessions

    Since we like type checking and auto-completion when coding etc. we're using instances of pydantic BaseModel
    to hold information that is eventually stored (by the works of the Flask SessionManager) in Redis.

    Different eduID services have their own "namespaces". Services are permitted to _read_ from other services
    namespaces, but not write to them. This is not enforced programmatically, but just a principle to adhere to.

    An EduidSession contains these "parts":

      _session          The backend session object. Has a dict-like interface for session data.
      _namespaces       A pydantic BaseModel object containing instances of session namespaces for different services.
                        Do not use these directly.
      idp, authn etc.   Properties to facilitate access to session namespaces. Will load data from _session into
                        _namespaces when first accessed.
      __setitem__       Stores data in the dict-like _session.
      __getitem__       Retrieves data from _session.
      persist()         The function called by the Flask SessionManager to save the session. Will serialise the
                        instances in _namespaces back into _session.

    So, the idea is that while we can't stop Flask from using the session in a dict-like fashion,
    all eduID services use the session through the namespace properties (idp, authn, etc.) with full typing
    and auto-complete support, and then Flask will call persist() which will store the data in the backend session.
    """

    def __init__(self, app: EduIDBaseApp, meta: SessionMeta, base_session: RedisEncryptedSession, new: bool = False):
        """
        :param app: the flask app
        :param meta: Session metadata
        :param base_session: The underlying session object
        :param new: whether the session is new or not.
        """
        super().__init__()
        self.app = app
        self.meta = meta
        self._session = base_session
        self._created = time()
        self._invalidated = False

        # From SessionMixin
        self.new = new
        self.modified = False

        # Namespaces, initialised lazily when accessed through properties
        self._namespaces = EduidNamespaces()

    def __str__(self):
        # Include hex(id(self)) for now to troubleshoot clobbered sessions
        return (
            f'<{self.__class__.__name__} at {hex(id(self))}: new={self.new}, '
            f'modified={self.modified}, cookie={self.short_id}>'
        )

    def __getitem__(self, key, default=None):
        return self._session.__getitem__(key, default=None)

    def __setitem__(self, key: str, value: Any):
        if key not in self._session or self._session[key] != value:
            self._session[key] = value
            logger.debug(f'SET {self}[{key}] = {value}')
            self.modified = True

    def __delitem__(self, key):
        if key in self._session:
            del self._session[key]
            logger.debug(f'DEL {self}[{key}]')
            self.modified = True

    def __iter__(self):
        return self._session.__iter__()

    def __len__(self):
        return len(self._session)

    def __contains__(self, key):
        return self._session.__contains__(key)

    @property
    def short_id(self) -> str:
        """ Short version of the cookie value for use in logging """
        return self.meta.cookie_val[:9] + '...'

    @property
    def permanent(self):
        return True

    @permanent.setter
    def permanent(self, value):
        # EduidSessions are _always_ permanent
        pass

    @property
    def common(self) -> Common:
        if not self._namespaces.common:
            self._namespaces.common = Common.from_dict(self._session.get('common', {}))
        return self._namespaces.common

    @property
    def mfa_action(self) -> MfaAction:
        if not self._namespaces.mfa_action:
            self._namespaces.mfa_action = MfaAction.from_dict(self._session.get('mfa_action', {}))
        return self._namespaces.mfa_action

    @mfa_action.deleter
    def mfa_action(self):
        """ When an MFA action is completed, it is removed entirely from the session """
        self._namespaces.mfa_action = None
        del self['mfa_action']

    @property
    def signup(self) -> Signup:
        if not self._namespaces.signup:
            self._namespaces.signup = Signup.from_dict(self._session.get('signup', {}))
        return self._namespaces.signup

    @property
    def actions(self) -> Actions:
        if not self._namespaces.actions:
            self._namespaces.actions = Actions.from_dict(self._session.get('actions', {}))
        return self._namespaces.actions

    @property
    def reset_password(self) -> ResetPasswordNS:
        if not self._namespaces.reset_password:
            self._namespaces.reset_password = ResetPasswordNS.from_dict(self._session.get('reset_password', {}))
        return self._namespaces.reset_password

    @property
    def security(self) -> SecurityNS:
        if not self._namespaces.security:
            self._namespaces.security = SecurityNS.from_dict(self._session.get('security', {}))
        return self._namespaces.security

    @property
    def idp(self) -> IdP_Namespace:
        if not self._namespaces.idp:
            self._namespaces.idp = IdP_Namespace.from_dict(self._session.get('idp', {}))
        return self._namespaces.idp

    @property
    def eidas(self) -> Eidas_Namespace:
        if not self._namespaces.eidas:
            self._namespaces.eidas = Eidas_Namespace.from_dict(self._session.get('eidas', {}))
        return self._namespaces.eidas

    @property
    def authn(self) -> Authn_Namespace:
        if not self._namespaces.authn:
            self._namespaces.authn = Authn_Namespace.from_dict(self._session.get('authn', {}))
        return self._namespaces.authn

    @property
    def created(self):
        """
        Created timestamp
        """
        return self._created

    def renew_ttl(self, renew_backend: bool) -> None:
        """
        Reset the ttl for the session, both in the cookie and
        (if `renew_backend==True`) in the redis backend.

        :param renew_backend: whether to renew the ttl in the redis backend
        """
        if not self.modified:
            self.modified = True
            if renew_backend:
                self._session.renew_ttl()

    def invalidate(self):
        """
        Invalidate the session. Clear the data from redis,
        and set an empty session cookie.
        """
        self.modified = True
        self._invalidated = True
        self._session.clear()

    def set_cookie(self, response):
        """
        Set the session cookie.

        :param response: the response object to carry the cookie
        :type response: flask.Response
        """
        if self._invalidated:
            response.delete_cookie(
                key=self.app.conf.flask.session_cookie_name,
                path=self.app.conf.flask.session_cookie_path,
                domain=self.app.conf.flask.session_cookie_domain,
            )
            return
        response.set_cookie(
            key=self.app.conf.flask.session_cookie_name,
            value=self.meta.cookie_val,
            domain=self.app.conf.flask.session_cookie_domain,
            path=self.app.conf.flask.session_cookie_path,
            secure=self.app.conf.flask.session_cookie_secure,
            httponly=self.app.conf.flask.session_cookie_httponly,
            samesite=self.app.conf.flask.session_cookie_samesite,
            max_age=self.app.conf.flask.permanent_session_lifetime,
        )

    def new_csrf_token(self) -> str:
        # only produce one csrf token by request
        if '_csrft_' not in self:
            token = os.urandom(20).hex()
            self['_csrft_'] = token
        return self['_csrft_']

    def get_csrf_token(self) -> str:
        token = self.get('_csrft_', None)
        if token is None:
            token = self.new_csrf_token()
        return token

    def _serialize_namespaces(self) -> None:
        """ Serialise all the namespace instances in self._namespaces.

        The __setitem__ function on `self' will essentially write the data into the backend session (self._session).
        """
        for k, value in self._namespaces.dict(exclude_none=True).items():
            this = getattr(self._namespaces, k)
            if isinstance(this, TimestampedNS):
                if k in self:
                    _old = self[k]
                if k in self and self[k] != value:
                    # update timestamp on change
                    this.ts = utc_now()
                    value = this.dict(exclude_none=True)
            self[k] = value

    def persist(self):
        """
        Store the session data in the redis backend,
        and renew the ttl for it.

        Check that session_id exists - when e.g. the account is being terminated,
        the session has already been invalidated at this point.
        """
        if self._invalidated:
            logger.debug('Not saving invalidated session')
            return

        # Serialize namespace instances back into self._session
        self._serialize_namespaces()

        if self.modified:
            logger.debug(f'Saving session {self}')
            self._session.commit()
            self.new = False
            self.modified = False
            if self.app.debug or self.app.conf.testing:
                _saved_data = json.dumps(self._session.to_dict(), indent=4, sort_keys=True, cls=EduidJSONEncoder)
                logger.debug(f'Saved session {self}:\n{_saved_data}')


class SessionFactory(SessionInterface):
    """
    Session factory, implementing flask.session.SessionInterface,
    to provide eduID redis-based sessions to the APIs.

    :param config: the configuration for the session
    """

    def __init__(self, config: EduIDBaseAppConfig):
        if config.flask.secret_key is None:
            raise BadConfiguration('flask.secret_key not set in config')

        ttl = 2 * config.flask.permanent_session_lifetime
        self.manager = SessionManager(config.redis_config, ttl=ttl, app_secret=config.flask.secret_key)

    # Return type not specified because 'Return type of "open_session" incompatible with supertype "SessionInterface"'
    def open_session(self, app: EduIDBaseApp, request: FlaskRequest):  # -> EduidSession:
        """
        See flask.session.SessionInterface
        """
        # Load token from cookie
        cookie_name = app.conf.flask.session_cookie_name
        cookie_val = request.cookies.get(cookie_name, None)
        logger.debug(f'Session cookie {cookie_name} == {cookie_val}')

        _meta = None
        _load_existing = False
        if cookie_val:
            try:
                _meta = SessionMeta.from_cookie(cookie_val, app_secret=self.manager.secret)
                _load_existing = True
            except ValueError as e:
                # Session cookie loading failed
                logger.debug(f'Could not load SessionMeta from cookie: {e}')

        if _meta is None:
            # No session cookie or cookie loading failed, create a new SessionMeta
            _meta = SessionMeta.new(app_secret=self.manager.secret)
            logger.debug('New SessionMeta initialized')

        base_session = None
        if _load_existing:
            # Try and load existing session identified by browser provided cookie
            try:
                base_session = self.manager.get_session(meta=_meta, new=False)
                logger.debug(f'Loaded existing session {base_session}')
            except KeyError:
                logger.debug(f'No session found using cookie {cookie_val}, will create a new one')

        new = False
        if not base_session:
            logger.debug(f'Creating new session with cookie {_meta.cookie_val}')
            base_session = self.manager.get_session(meta=_meta, new=True)
            new = True

        sess = EduidSession(app, _meta, base_session, new=new)
        logger.debug(f'Created/loaded session {sess} with base_session {base_session}')
        if app.debug or app.conf.testing:
            _loaded_data = json.dumps(sess._session.to_dict(), indent=4, sort_keys=True)
            logger.debug(f'Loaded session {sess}:\n{_loaded_data}')
        return sess

    def save_session(self, app: EduIDBaseApp, sess: EduidSession, response: FlaskResponse) -> None:
        """
        See flask.session.SessionInterface
        """
        if sess is None:
            # Do not try to save the session and set the cookie if the session is not initialized
            # We have seen this happen...
            logger.warning(f'Session was not initialized when reaching save_session: sess={sess}')
            return None
        try:
            sess.persist()
        except SessionOutOfSync:
            app.stats.count('session_out_of_sync_error')
            logger.error(f'Commit of session {sess} failed because it has been changed by someone else')
            diff_c = 0
            # For debugging purposes, load the session from the backend anew and show what was changed
            # by someone else
            try:
                session_now = self.manager.get_session(meta=sess.meta, new=False)
                for k, v in sess.items():
                    if k in session_now:
                        # Serialise my data so it can be compared to the serialised data in session_now
                        my_v = json.loads(json.dumps(v, cls=EduidJSONEncoder))
                        if my_v != session_now[k]:
                            logger.error(
                                f'Session key {k} changed, mine\n{pprint.pformat(my_v)}\n'
                                f'in db:\n{pprint.pformat(session_now[k])}'
                            )
                            diff_c += 1
                    else:
                        logger.error(f'Session key {k} disappeared, mine {sess[k]}')
                        diff_c += 1
                for k, v in session_now.items():
                    if k not in sess:
                        logger.error(f'Session key {k} added in db: {session_now[k]}')
                        diff_c += 1
            except KeyError:
                logger.error('Failed loading session from backend for comparison')
            logger.error(f'Number of differences: {diff_c}')
            raise
        sess.set_cookie(response)
