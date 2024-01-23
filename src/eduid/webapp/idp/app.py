from typing import Any, Mapping, Optional, cast

from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.userdb.actions.tou.userdb import ToUUserDB

# from eduid.userdb.actions.tou import ToUUserDB
from eduid.userdb.idp import IdPUserDb
from eduid.webapp.common.api import translation
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.authn.utils import init_pysaml2
from eduid.webapp.idp import idp_authn
from eduid.webapp.idp.known_device import KnownDeviceDB
from eduid.webapp.idp.other_device.db import OtherDeviceDB
from eduid.webapp.idp.settings.common import IdPConfig
from eduid.webapp.idp.sso_cache import SSOSessionCache
from eduid.webapp.idp.sso_session import SSOSession, get_sso_session

__author__ = "ft"


class IdPApp(EduIDBaseApp):
    def __init__(self, config: IdPConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        self.conf = config

        # Init dbs
        # self.private_userdb = IdPUserDB(self.conf.mongo_uri)
        # Initiate external modules
        self.babel = translation.init_babel(self)

        # Connecting to MongoDB can take some time if the replica set is not fully working.
        # Log both 'starting' and 'started' messages.
        self.logger.info("eduid-IdP server starting")

        self.logger.debug(f"Loading PySAML2 server using cfgfile {config.pysaml2_config}")
        self.IDP = init_pysaml2(config.pysaml2_config)

        if config.mongo_uri is None:
            raise RuntimeError("Mongo URI is not optional for the IdP")
        self.sso_sessions = SSOSessionCache(config.mongo_uri)

        self.authn_info_db = None

        self.userdb = IdPUserDb(db_uri=config.mongo_uri)
        self.authn = idp_authn.IdPAuthn(config=config, userdb=self.userdb)
        self.tou_db = ToUUserDB(config.mongo_uri)
        self.other_device_db = OtherDeviceDB(config.mongo_uri)
        self.known_device_db = KnownDeviceDB(
            config.mongo_uri,
            app_secretbox_key=config.known_devices_secret_key,
            new_ttl=config.known_devices_new_ttl,
            ttl=config.known_devices_ttl,
        )

        # Init celery
        self.am_relay = AmRelay(config)

        self.logger.info("eduid-IdP application started")

    # OLD way, call sso_session.get_sso_session() directly instead, or use the @uses_sso_session decorator
    def _lookup_sso_session(self) -> Optional[SSOSession]:
        """
        Locate any existing SSO session for this request.

        :returns: SSO session if found (and valid)
        """
        return get_sso_session()


current_idp_app = cast(IdPApp, current_app)


def init_idp_app(name: str = "idp", test_config: Optional[Mapping[str, Any]] = None) -> IdPApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override configuration - used in tests.

    :return: the flask app
    """
    config = load_config(typ=IdPConfig, app_name=name, ns="webapp", test_config=test_config)

    app = IdPApp(config, handle_exceptions=False)

    # Register views
    from eduid.webapp.idp.views.error_info import error_info_views
    from eduid.webapp.idp.views.known_device import known_device_views
    from eduid.webapp.idp.views.mfa_auth import mfa_auth_views
    from eduid.webapp.idp.views.misc import misc_views
    from eduid.webapp.idp.views.next import next_views
    from eduid.webapp.idp.views.pw_auth import pw_auth_views
    from eduid.webapp.idp.views.saml import saml_views
    from eduid.webapp.idp.views.tou import tou_views
    from eduid.webapp.idp.views.use_other import other_device_views

    app.register_blueprint(known_device_views)
    app.register_blueprint(mfa_auth_views)
    app.register_blueprint(misc_views)
    app.register_blueprint(next_views)
    app.register_blueprint(other_device_views)
    app.register_blueprint(pw_auth_views)
    app.register_blueprint(saml_views)
    app.register_blueprint(tou_views)
    app.register_blueprint(error_info_views)

    from eduid.webapp.idp.exceptions import init_exception_handlers

    app = init_exception_handlers(app)

    app.logger.info(f"{name} initialized")
    return app
