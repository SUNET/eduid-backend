from collections.abc import Mapping
from typing import Any, cast

from flask import current_app

from eduid.common.clients import SCIMClient
from eduid.common.config.exceptions import BadConfiguration
from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.rpc.mail_relay import MailRelay
from eduid.queue.db.message import MessageDB
from eduid.userdb.logs import ProofingLog
from eduid.userdb.signup import SignupInviteDB, SignupUserDB
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.captcha import init_captcha
from eduid.webapp.signup.settings.common import SignupConfig


class SignupApp(EduIDBaseApp):
    def __init__(self, config: SignupConfig, **kwargs):
        super().__init__(config, **kwargs)

        self.conf = config

        self.am_relay = AmRelay(config)
        self.mail_relay = MailRelay(config)

        self.captcha = init_captcha(config)

        self.scim_clients: dict[str, SCIMClient] = {}

        self.private_userdb = SignupUserDB(config.mongo_uri, auto_expire=config.private_userdb_auto_expire)
        self.proofing_log = ProofingLog(config.mongo_uri)
        self.invite_db = SignupInviteDB(config.mongo_uri)
        self.messagedb = MessageDB(config.mongo_uri)

    def get_scim_client_for(self, data_owner: str) -> SCIMClient:
        if self.conf.gnap_auth_data is None or self.conf.scim_api_url is None:
            raise BadConfiguration("No auth server configuration available")

        if data_owner not in self.scim_clients:
            access_request = [{"type": "scim-api", "scope": data_owner}]
            client_auth_data = self.conf.gnap_auth_data.copy(update={"access": access_request})
            self.scim_clients[data_owner] = SCIMClient(scim_api_url=self.conf.scim_api_url, auth_data=client_auth_data)
        return self.scim_clients[data_owner]


current_signup_app: SignupApp = cast(SignupApp, current_app)


def signup_init_app(name: str = "signup", test_config: Mapping[str, Any] | None = None) -> SignupApp:
    """
    Create an instance of an eduid signup app.

    Note that we use EduIDBaseApp as the class for the Flask app,
    since obviously the signup app is used unauthenticated.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config. Used in test cases.
    """
    config = load_config(typ=SignupConfig, app_name=name, ns="webapp", test_config=test_config)

    app = SignupApp(config)

    app.logger.info(f"Init {app}...")

    from eduid.webapp.signup.views import signup_views

    app.register_blueprint(signup_views)

    return app
