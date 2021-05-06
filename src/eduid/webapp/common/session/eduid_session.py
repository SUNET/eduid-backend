from __future__ import annotations

import json
import logging
import os
from collections.abc import MutableMapping
from time import time
from typing import TYPE_CHECKING, Any, Optional

from flask import Request as FlaskRequest
from flask import Response as FlaskResponse
from flask.sessions import SessionInterface, SessionMixin

from eduid.common.config.base import EduIDBaseAppConfig
from eduid.common.config.exceptions import BadConfiguration
from eduid.webapp.common.session.logindata import SSOLoginData
from eduid.webapp.common.session.meta import SessionMeta
from eduid.webapp.common.session.namespaces import (
    Actions,
    Common,
    IdP_Namespace,
    MfaAction,
    ResetPasswordNS,
    SessionNSBase,
    Signup,
)
from eduid.webapp.common.session.redis_session import RedisEncryptedSession, SessionManager, SessionOutOfSync

if TYPE_CHECKING:
    # From https://stackoverflow.com/a/39757388
    # The TYPE_CHECKING constant is always False at runtime, so the import won't be evaluated, but mypy
    # (and other type-checking tools) will evaluate the contents of this block.
    from eduid.webapp.common.api.app import EduIDBaseApp

    # keep pycharm from optimising away the above import
    assert EduIDBaseApp

logger = logging.getLogger(__name__)


class EduidSession(SessionMixin, MutableMapping):
    """
    Session implementing the flask.sessions.SessionMixin interface.
    It uses the Session defined in eduid.webapp.common.session.session
    to store the session data in redis.
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
        self.session = base_session
        self._created = time()
        self._invalidated = False

        # From SessionMixin
        self.new = new
        self.modified = False

        # Namespaces
        self._common: Optional[Common] = None
        self._mfa_action: Optional[MfaAction] = None
        self._signup: Optional[Signup] = None
        self._actions: Optional[Actions] = None
        self._sso_ticket: Optional[SSOLoginData] = None
        self._reset_password: ResetPasswordNS
        self._idp: IdP_Namespace

    def __str__(self):
        # Include hex(id(self)) for now to troubleshoot clobbered sessions
        return (
            f'<{self.__class__.__name__} at {hex(id(self))}: new={self.new}, '
            f'modified={self.modified}, cookie={self.short_id}>'
        )

    def __getitem__(self, key, default=None):
        return self.session.__getitem__(key, default=None)

    def __setitem__(self, key: str, value: Any):
        if key not in self.session or self.session[key] != value:
            self.session[key] = value
            logger.debug(f'SET {self}[{key}] = {value}')
            self.modified = True

    def __delitem__(self, key):
        if key in self.session:
            del self.session[key]
            logger.debug(f'DEL {self}[{key}]')
            self.modified = True

    def __iter__(self):
        return self.session.__iter__()

    def __len__(self):
        return len(self.session)

    def __contains__(self, key):
        return self.session.__contains__(key)

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
    def common(self) -> Optional[Common]:
        if not self._common:
            self._common = Common.from_dict(self._session.get('_common', {}))
            self._common = Common.from_dict(self.session.get('_common', {}))
        return self._common

    @common.setter
    def common(self, value: Optional[Common]):
        if not self._common:
            self._common = value

    @property
    def mfa_action(self) -> Optional[MfaAction]:
        if not self._mfa_action:
            self._mfa_action = MfaAction.from_dict(self._session.get('_mfa_action', {}))
            self._mfa_action = MfaAction.from_dict(self.session.get('_mfa_action', {}))
        return self._mfa_action

    @mfa_action.setter
    def mfa_action(self, value: Optional[MfaAction]):
        if not self._mfa_action:
            self._mfa_action = value

    @mfa_action.deleter
    def mfa_action(self):
        self._mfa_action = None
        self._session.pop('_mfa_action', None)
        self.session.pop('_mfa_action', None)
        self.modified = True

    @property
    def signup(self) -> Optional[Signup]:
        if not self._signup:
            self._signup = Signup.from_dict(self._session.get('_signup', {}))
            self._signup = Signup.from_dict(self.session.get('_signup', {}))
        return self._signup

    @signup.setter
    def signup(self, value: Optional[Signup]):
        if not self._signup:
            self._signup = value

    @property
    def actions(self) -> Optional[Actions]:
        if not self._actions:
            self._actions = Actions.from_dict(self._session.get('_actions', {}))
            self._actions = Actions.from_dict(self.session.get('_actions', {}))
        return self._actions

    @actions.setter
    def actions(self, value: Optional[Actions]):
        if not self._actions:
            self._actions = value

    @property
    def sso_ticket(self) -> Optional[SSOLoginData]:
        if not self._sso_ticket:
            data = self._session.get('_sso_ticket', {})
            data = self.session.get('_sso_ticket', {})
            if 'key' in data:
                try:
                    self._sso_ticket = SSOLoginData.from_dict(data)
                except Exception:
                    logger.exception('Failed parsing SSOLoginData')
                    self._sso_ticket = None
            return self._sso_ticket
        return None

    @sso_ticket.setter
    def sso_ticket(self, value: Optional[SSOLoginData]):
        if not self._sso_ticket:
            self._sso_ticket = value

    @property
    def reset_password(self) -> ResetPasswordNS:
        if not hasattr(self, '_reset_password') or not self._reset_password:
            self._reset_password = ResetPasswordNS.from_dict(self._session.get('_reset_password', {}))
            self._reset_password = ResetPasswordNS.from_dict(self.session.get('_reset_password', {}))
        return self._reset_password

    @reset_password.setter
    def reset_password(self, value: ResetPasswordNS):
        if not isinstance(value, ResetPasswordNS):
            raise TypeError('reset_password value must be a ResetPasswordNS')
        if not hasattr(self, '_reset_password') or not self._reset_password:
            self._reset_password = value
        else:
            raise ValueError('ResetPasswordNS already initialised')

    @property
    def idp(self) -> IdP_Namespace:
        if not hasattr(self, '_idp') or not self._idp:
            # Convert dict to dataclass instance
            self._idp = IdP_Namespace.from_dict(self.session.get('_idp', {}))
        return self._idp

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
                self.session.renew_ttl()

    def invalidate(self):
        """
        Invalidate the session. Clear the data from redis,
        and set an empty session cookie.
        """
        self.modified = True
        self._invalidated = True
        self.session.clear()

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
        for key in self.__dict__.keys():
            if key.startswith('_'):  # Keep SessionNS in sunder attrs
                attr = getattr(self, key)
                try:
                    # serialise using to_dict() if the object has such a method
                    self[key] = attr.to_dict()
                except AttributeError:
                    pass

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

        # Serialize namespace dataclasses to see if their content changed
        self._serialize_namespaces()

        # TODO: Remove self.new below at a later stage
        #   Only save a session if it is modified
        #   Don't save it just because it is new, this is to not
        #   save empty sessions for every call to the backend
        if self.new or self.modified:
            logger.debug(f'Saving session {self}')
            self.session.commit()
            self.new = False
            self.modified = False
            if self.app.debug or self.app.conf.testing:
                _saved_data = json.dumps(self.session.to_dict(), indent=4, sort_keys=True)
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
            _loaded_data = json.dumps(sess.session.to_dict(), indent=4, sort_keys=True)
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
            raise
        sess.set_cookie(response)
