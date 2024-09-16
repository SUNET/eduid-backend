from collections.abc import Mapping
from typing import Any, Optional

from flask import Blueprint, abort, current_app, request

from eduid.common.config.base import EduIDBaseAppConfig, EduidEnvironment, MagicCookieMixin
from eduid.common.config.parsers import load_config
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.session.eduid_session import SessionFactory

test_views = Blueprint("test", __name__)


@test_views.route("/get-code", methods=["GET"])
def get_code():
    current_app.logger.info("Endpoint get_code called")
    try:
        if check_magic_cookie(current_app.conf):
            eppn = request.args.get("eppn")
            result = f"dummy-code-for-{eppn}"
            current_app.logger.info(f"Endpoint get_code result: {result}")
            return result
    except Exception as e:
        current_app.logger.exception(f"get_code failed: {e}")

    current_app.logger.info("Endpoint get_code aborting with a HTTP 400 error")
    abort(400)


class BackdoorTestConfig(EduIDBaseAppConfig, MagicCookieMixin):
    pass


class BackdoorTestApp(EduIDBaseApp):
    def __init__(self, config: BackdoorTestConfig):
        super().__init__(config)

        self.conf = config


class BackdoorTests(EduidAPITestCase[BackdoorTestApp]):
    def setUp(  # type: ignore[override]
        self,
        *args: list[Any],
        users: Optional[list[str]] = None,
        copy_user_to_private: bool = False,
        **kwargs: dict[str, Any],
    ) -> None:
        super().setUp(*args, users=users, copy_user_to_private=copy_user_to_private, **kwargs)

        self.test_get_url = "/get-code?eppn=pepin-pepon"
        self.test_app_domain = "test.localhost"

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        """
        Called from the parent class, so that we can update the configuration
        according to the needs of this test case.
        """
        config.update(
            {
                "available_languages": {"en": "English", "sv": "Svenska"},
                "no_authn_urls": [r"/get-code"],
                "environment": "dev",
                "magic_cookie_name": "magic-cookie",
                "magic_cookie": "magic-cookie",
            }
        )
        return config

    def load_app(self, config: Mapping[str, Any]) -> BackdoorTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask app for this test case.
        """
        _config = load_config(typ=BackdoorTestConfig, app_name="testing", ns="webapp", test_config=config)
        app = BackdoorTestApp(_config)
        app.register_blueprint(test_views)
        app.session_interface = SessionFactory(app.conf)
        return app

    def test_backdoor_get_code(self):
        """"""
        with self.session_cookie_and_magic_cookie_anon(self.browser) as client:
            response = client.get(self.test_get_url)
            assert response.data == b"dummy-code-for-pepin-pepon"

    def test_no_backdoor_in_pro(self):
        """"""
        self.app.conf.environment = EduidEnvironment("production")

        with self.session_cookie_and_magic_cookie_anon(self.browser) as client:
            response = client.get(self.test_get_url)
            self.assertEqual(response.status_code, 400)

    def test_no_backdoor_without_cookie(self):
        """"""
        with self.session_cookie_anon(self.browser) as client:
            response = client.get(self.test_get_url)
            self.assertEqual(response.status_code, 400)

    def test_wrong_cookie_no_backdoor(self):
        """"""
        with self.session_cookie_and_magic_cookie_anon(self.browser, magic_cookie_value="no-magic") as client:
            response = client.get(self.test_get_url)
            self.assertEqual(response.status_code, 400)

    def test_no_magic_cookie_no_backdoor(self):
        """"""
        self.app.conf.magic_cookie = ""

        with self.session_cookie_and_magic_cookie_anon(self.browser) as client:
            response = client.get(self.test_get_url)
            self.assertEqual(response.status_code, 400)

    def test_no_magic_cookie_name_no_backdoor(self):
        """"""
        self.app.conf.magic_cookie_name = ""

        with self.session_cookie_and_magic_cookie_anon(self.browser, magic_cookie_name="wrong_name") as client:
            response = client.get(self.test_get_url)
            self.assertEqual(response.status_code, 400)
