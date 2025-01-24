from __future__ import annotations

import logging
import logging.config
import pprint
import sys
import traceback
from collections.abc import Generator, Iterable, Mapping
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta
from typing import Any, Generic, TypeVar, cast

from flask.testing import FlaskClient
from werkzeug.test import TestResponse

from eduid.common.config.base import EduIDBaseAppConfig, FrontendAction, MagicCookieMixin, RedisConfig
from eduid.common.misc.timeutil import utc_now
from eduid.common.rpc.msg_relay import FullPostalAddress, NavetData
from eduid.common.testing_base import CommonTestCase
from eduid.userdb import User
from eduid.userdb.credentials import U2F, Webauthn
from eduid.userdb.db import BaseDB
from eduid.userdb.element import ElementKey
from eduid.userdb.fixtures.fido_credentials import u2f_credential, webauthn_credential
from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.identity import IdentityType
from eduid.userdb.logs.db import ProofingLog
from eduid.userdb.proofing.state import NinProofingState
from eduid.userdb.testing import MongoTemporaryInstance, SetupConfig
from eduid.userdb.userdb import UserDB
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.messages import AuthnStatusMsg, TranslatableMsg
from eduid.webapp.common.api.schemas.authn_status import AuthnActionStatus
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction
from eduid.webapp.common.session import EduidSession
from eduid.webapp.common.session.namespaces import SP_AuthnRequest
from eduid.webapp.common.session.testing import RedisTemporaryInstance
from eduid.workers.msg.tasks import MessageSender

logger = logging.getLogger(__name__)

TEST_CONFIG = {
    "debug": True,
    "testing": True,
    "secret_key": "mysecretkey",
    "session_cookie_name": "sessid",
    "session_cookie_domain": "test.localhost",
    "session_cookie_path": "/",
    "session_cookie_httponly": False,
    "session_cookie_secure": False,
    "permanent_session_lifetime": 60,
    "server_name": "test.localhost",
    "propagate_exceptions": True,
    "preserve_context_on_exception": True,
    "trap_http_exceptions": True,
    "trap_bad_request_errors": True,
    "preferred_url_scheme": "http",
    "json_as_ascii": False,
    "json_sort_keys": True,
    "jsonify_prettyprint_regular": True,
    "mongo_uri": "mongodb://localhost",
    "eduid_site_name": "eduID TESTING",
    "celery": {
        "broker_transport": "memory",
        "broker_url": "memory://",
        "task_eager_propagates": True,
        "task_always_eager": True,
        "result_backend": "cache",
        "cache_backend": "memory",
    },
    "logging_config": {
        "loggers": {
            "saml2": {"level": "WARNING"},
            "xmlsec": {"level": "INFO"},
            "urllib3": {"level": "INFO"},
            "pymongo.serverSelection": {"level": "INFO"},
            "pymongo.connection": {"level": "INFO"},
            "pymongo.command": {"level": "INFO"},
            "pymongo.topology": {"level": "INFO"},
            "eduid.webapp.common.session": {"level": "INFO"},
            "eduid.userdb.userdb.extra_debug": {"level": "INFO"},
            "eduid.userdb.db.extra_debug": {"level": "INFO"},
            "eduid.userdb": {"level": "INFO"},
        }
    },
}


TTestAppVar = TypeVar("TTestAppVar", bound=EduIDBaseApp)


class EduidAPITestCase(CommonTestCase, Generic[TTestAppVar]):
    """
    Base Test case for eduID APIs.

    See the `load_app` and `update_config` methods below before subclassing.
    """

    app: TTestAppVar
    browser: CSRFTestClient

    def setUp(self, config: SetupConfig | None = None) -> None:
        if config is None:
            config = SetupConfig()
        # test users
        if config.users is None:
            config.users = ["hubba-bubba"]

        _users = UserFixtures()
        _standard_test_users = {
            "hubba-bubba": _users.new_user_example,
            "hubba-baar": _users.new_unverified_user_example,
            "hubba-fooo": _users.new_completed_signup_user_example,
        }

        # Make a list of User object to be saved to the new temporary mongodb instance
        am_users = [_standard_test_users[x] for x in config.users]

        config.am_users = am_users
        super().setUp(config=config)

        self.user: User | None = None

        # Load the user from the database so that it can be saved there again in tests
        _test_user = self.amdb.get_user_by_eppn(config.users[0])
        # Initialize some convenience variables on self based on the first user in `users'
        self.test_user = _test_user
        self.test_user_data = self.test_user.to_dict()
        self.test_user_eppn = self.test_user_data["eduPersonPrincipalName"]

        # Set up Redis for shared sessions
        self.redis_instance = RedisTemporaryInstance.get_instance()
        # settings
        test_config = deepcopy(TEST_CONFIG)
        self.settings: dict[str, Any] = self.update_config(test_config)
        self.settings["redis_config"] = RedisConfig(host="localhost", port=self.redis_instance.port)
        assert isinstance(self.tmp_db, MongoTemporaryInstance)  # please mypy
        self.settings["mongo_uri"] = self.tmp_db.uri

        self.app = self.load_app(self.settings)
        if isinstance(self.app, EduIDBaseApp):
            self.app.test_client_class = CSRFTestClient
            self.browser = cast(CSRFTestClient, self.app.test_client())

        # Helper constants
        self.content_type_json = "application/json"
        self.test_domain = "test.localhost"

        if config.copy_user_to_private:
            data = self.test_user.to_dict()
            _private_userdb = getattr(self.app, "private_userdb")
            assert isinstance(_private_userdb, UserDB)
            logging.info(f"Copying test-user {self.test_user} to private_userdb {_private_userdb}")
            _private_userdb.save(_private_userdb.user_from_dict(data=data))

    def tearDown(self) -> None:
        try:
            # Reset anything that looks like a BaseDB, for the next test class.
            for this in vars(self.app).values():
                if isinstance(this, BaseDB):
                    this._drop_whole_collection()
        except Exception as exc:
            sys.stderr.write(f"Exception in tearDown: {exc!s}\n{exc!r}\n")
            traceback.print_exc()
        super(CommonTestCase, self).tearDown()
        # XXX reset redis

    def load_app(self, config: dict[str, Any]) -> TTestAppVar:
        """
        Method that must be implemented by any subclass, where the
        flask app must be imported and returned.
        This is so we can set  the test configuration in environment variables
        before the flask app loads its config from a file.
        """
        raise NotImplementedError(
            "Classes extending EduidAPITestCase must provide a method where they import the flask app and return it."
        )

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        """
        Method that can be overridden by any subclass,
        where it can add configuration specific for that API
        before loading the app.

        :param config: original configuration

        :return: the updated configuration
        """
        # For tests, it makes sense to show relative time instead of datetime
        config["log_format"] = "{asctime} | {levelname:7} | {eppn:11} | {name:35} | {message}"
        return config

    @contextmanager
    def session_cookie(
        self,
        client: CSRFTestClient,
        eppn: str | None,
        logged_in: bool = True,
        domain: str | None = None,
        **kwargs: Any,
    ) -> Generator[CSRFTestClient, None, None]:
        if domain is None:
            domain = self.test_domain
        with client.session_transaction(**kwargs) as sess:
            if eppn is not None:
                sess.common.eppn = eppn
                sess.common.is_logged_in = logged_in
            assert isinstance(self.app, EduIDBaseApp)
            _conf = getattr(self.app, "conf")
            assert isinstance(_conf, EduIDBaseAppConfig)
            client.set_cookie(domain=domain, key=_conf.flask.session_cookie_name, value=sess.meta.cookie_val)
        yield client

    @contextmanager
    def session_cookie_anon(self, client: CSRFTestClient, **kwargs: Any) -> Generator[CSRFTestClient, None, None]:
        with self.session_cookie(client=client, eppn=None, **kwargs) as _client:
            yield _client

    @contextmanager
    def session_cookie_and_magic_cookie(
        self,
        client: CSRFTestClient,
        eppn: str | None,
        logged_in: bool = True,
        domain: str | None = None,
        magic_cookie_name: str | None = None,
        magic_cookie_value: str | None = None,
        **kwargs: Any,
    ) -> Generator[CSRFTestClient, None, None]:
        if domain is None:
            domain = self.test_domain
        assert isinstance(self.app, EduIDBaseApp)
        _conf = getattr(self.app, "conf")
        assert isinstance(_conf, MagicCookieMixin)
        if magic_cookie_name is None:
            assert _conf.magic_cookie_name is not None
            magic_cookie_name = _conf.magic_cookie_name
        if magic_cookie_value is None:
            assert _conf.magic_cookie is not None
            magic_cookie_value = _conf.magic_cookie
        with self.session_cookie(client=client, eppn=eppn, domain=domain, logged_in=logged_in, **kwargs) as _client:
            _client.set_cookie(domain=domain, key=magic_cookie_name, value=magic_cookie_value)
            yield _client

    @contextmanager
    def session_cookie_and_magic_cookie_anon(
        self,
        client: CSRFTestClient,
        magic_cookie_name: str | None = None,
        magic_cookie_value: str | None = None,
        **kwargs: Any,
    ) -> Generator[CSRFTestClient, None, None]:
        with self.session_cookie_and_magic_cookie(
            client=client,
            eppn=None,
            magic_cookie_name=magic_cookie_name,
            magic_cookie_value=magic_cookie_value,
            **kwargs,
        ) as _client:
            yield _client

    def request_user_sync(self, private_user: User, app_name_override: str | None = None) -> bool:
        """
        Updates the central db user with data from the private db user.

        :param private_user: User to save in central db
        :type private_user: Private subclass of eduid_db.user.User
        :return: True
        """
        logger.info(f"Saving user {private_user} to central userdb using test-request_user_sync() method")

        central_user = self.app.central_userdb.get_user_by_id(private_user.user_id)
        private_user_dict = private_user.to_dict()
        replace_locked: IdentityType | None = None
        # fix signup_user data
        if "proofing_reference" in private_user_dict:
            del private_user_dict["proofing_reference"]

        if "replace_locked" in private_user_dict:
            replace_locked = private_user_dict["replace_locked"]
            del private_user_dict["replace_locked"]

        if central_user is None:
            # This is a new user, create a new user in the central db
            self.app.central_userdb.save(User.from_dict(private_user_dict))
            return True

        central_user_dict = central_user.to_dict()
        central_user_dict.update(private_user_dict)

        # Iterate over all top level keys and remove those missing
        for key in list(central_user_dict.keys()):
            if key not in private_user_dict:
                central_user_dict.pop(key, None)

        # create updated user
        user = User.from_dict(data=central_user_dict)

        # add locked identity the same way as done in consistency checks in am
        for identity in user.identities.to_list():
            if identity.is_verified is False:
                # if the identity is not verified then locked identities does not matter
                continue
            locked_identity = user.locked_identity.find(identity.identity_type)
            # add new verified identity to locked identities
            if locked_identity is None:
                if identity.created_by is None:
                    identity.created_by = "test"
                user.locked_identity.add(identity)
                continue
            if replace_locked is locked_identity.identity_type:
                # replace the locked identity with the new verified identity
                if identity.created_by is None:
                    identity.created_by = "test"
                user.locked_identity.replace(identity)

        # Restore metadata that is necessary for the consistency checks in the save() function
        user.modified_ts = central_user.modified_ts
        user.meta.modified_ts = central_user.meta.modified_ts
        user.meta.version = central_user.meta.version
        user.meta.is_in_database = True

        self.app.central_userdb.save(user)
        return True

    def set_authn_action(
        self,
        eppn: str,
        frontend_action: FrontendAction,
        post_authn_action: AuthnAcsAction = AuthnAcsAction.login,
        age: timedelta = timedelta(seconds=30),
        finish_url: str | None = None,
        mock_mfa: bool = False,
        credentials_used: list[ElementKey] | None = None,
    ) -> None:
        if not finish_url:
            finish_url = "https://example.com/ext-return/{app_name}/{authn_id}"

        if credentials_used is None:
            credentials_used = []

        if mock_mfa:
            credentials_used = [ElementKey("mock_credential_one"), ElementKey("mock_credential_two")]

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                # Add authn data faking a reauthn event has taken place for this action
                sp_authn_req = SP_AuthnRequest(
                    post_authn_action=post_authn_action,
                    authn_instant=utc_now() - age,
                    frontend_action=frontend_action,
                    credentials_used=credentials_used,
                    finish_url=finish_url,
                )
                sess.authn.sp.authns[sp_authn_req.authn_id] = sp_authn_req

    def setup_signup_authn(self, eppn: str | None = None, user_created_at: datetime | None = None) -> None:
        if eppn is None:
            eppn = self.test_user_eppn
        if user_created_at is None:
            user_created_at = utc_now() - timedelta(minutes=3)
        # mock recent account creation from signup
        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                sess.signup.user_created = True
                sess.signup.user_created_at = user_created_at

    def add_security_key_to_user(
        self,
        eppn: str,
        keyhandle: str,
        token_type: str = "webauthn",
        created_ts: datetime = utc_now(),
        mfa_approved: bool = False,
    ) -> U2F | Webauthn:
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        mfa_token: U2F | Webauthn

        if token_type == "webauthn":
            mfa_token = deepcopy(webauthn_credential)
            mfa_token.mfa_approved = mfa_approved
        else:
            mfa_token = deepcopy(u2f_credential)

        mfa_token.created_ts = created_ts
        mfa_token.modified_ts = created_ts
        mfa_token.keyhandle = keyhandle
        mfa_token.no_created_ts_in_db = False
        mfa_token.no_modified_ts_in_db = False
        user.credentials.add(mfa_token)
        self.request_user_sync(user)
        return mfa_token

    @staticmethod
    def _get_all_navet_data() -> NavetData:
        return NavetData.model_validate(MessageSender.get_devel_all_navet_data())

    @staticmethod
    def _get_full_postal_address() -> FullPostalAddress:
        return FullPostalAddress.model_validate(MessageSender.get_devel_postal_address())

    def _check_must_authenticate_response(
        self,
        response: TestResponse,
        type_: str | None,
        frontend_action: FrontendAction,
        authn_status: AuthnActionStatus,
    ) -> None:
        """Check that a call to the API failed in the authentication stage."""
        meta = {
            "frontend_action": frontend_action.value,
            "authn_status": authn_status.value,
        }
        payload = {
            "message": AuthnStatusMsg.must_authenticate.value,
        }
        self._check_api_response(response, status=200, type_=type_, payload=payload, meta=meta)

    def _check_error_response(
        self,
        response: TestResponse,
        type_: str | None,
        msg: TranslatableMsg | None = None,
        error: Mapping[str, Any] | None = None,
        payload: Mapping[str, Any] | None = None,
    ) -> None:
        """Check that a call to the API failed in the data validation stage."""
        self._check_api_response(response, 200, type_=type_, message=msg, error=error, payload=payload)

    def _check_success_response(
        self,
        response: TestResponse,
        type_: str | None,
        msg: TranslatableMsg | None = None,
        payload: Mapping[str, Any] | None = None,
    ) -> None:
        """
        Check the message returned from an eduID webapp endpoint.
        """
        if response.json and response.json.get("error") is True:
            assert False is True, f"FluxResponse has error set to True: {response.json}"
        self._check_api_response(response, 200, type_=type_, message=msg, payload=payload)

    @staticmethod
    def get_response_payload(response: TestResponse) -> dict[str, Any]:
        """
        Perform some checks to make sure the response is a Flux Standard Action (FSA) response, and return the payload.
        """
        assert response.is_json, "Response is not JSON"
        _json: dict[str, Any] | None = response.json
        assert isinstance(_json, dict), "Response has invalid JSON"
        _type: str | None = _json.get("type")
        assert _type is not None, "Response has no type (is not an FSA response)"
        _payload: dict[str, Any] | None = _json.get("payload", {})
        assert isinstance(_payload, dict), "Response has invalid payload"
        return _payload

    @staticmethod
    def _check_api_response(
        response: TestResponse,
        status: int,
        type_: str | None,
        message: TranslatableMsg | None = None,
        error: Mapping[str, Any] | None = None,
        payload: Mapping[str, Any] | None = None,
        assure_not_in_payload: Iterable[str] | None = None,
        meta: Mapping[str, Any] | None = None,
    ) -> None:
        """
        Check data returned from an eduID webapp endpoint.

        This is expected to be a Flux Standard Action response, e.g.

        {'type': 'POST_LETTER_PROOFING_VERIFY_CODE_SUCCESS'},
         'payload': {'csrf_token': '1b0c34e9693e31a97dc478bbcde576098d58e847',
                     'message': 'letter.verification_success',
                     'nins': [{'number': '200001023456',
                               'primary': False,
                               'verified': False}],
                     'success': True}
        }

        If msg is provided, payload['message'] is validated against it.

        If payload is provided, the elements in it are verified to be present in the response 'payload'.
        Because of the ever-changing csrf_token, and to not make all previous tests fail when a new
        item is added to the payload in a response from some endpoint, we don't fail if there are more
        elements present in the response payload.

        :param response: The flask test Response instance
        :param status: Expected HTTP status code
        :param type_: Expected JSON 'type' element
        :param message: Expected JSON payload message element
        :param error: Expected JSON error message
        :param payload: Data expected to be found in the 'payload' of the response
        """

        def _assure_not_in_dict(d: Mapping[str, Any], unwanted_key: str) -> None:
            assert unwanted_key not in d, f"Key {unwanted_key} should not be in payload, but it is: {payload}"
            v2: Mapping[str, Any]
            for v2 in d.values():
                if isinstance(v2, dict):
                    _assure_not_in_dict(v2, unwanted_key)

        try:
            assert status == response.status_code, f"The HTTP response code was {response.status_code} not {status}"
            _json = response.json
            assert _json
            if type_ is not None:
                assert type_ == _json["type"], f"Wrong response type. expected: {type_}, actual: {_json['type']}"
            assert "payload" in _json, 'JSON body has no "payload" element'
            if message is not None:
                assert "message" in _json["payload"], 'JSON payload has no "message" element'
                _message_value = _json["payload"]["message"]
                assert (
                    message.value == _message_value
                ), f"Wrong message returned. expected: {message.value}, actual: {_message_value}"
            if error is not None:
                assert _json["error"] is True, "The Flux response was supposed to have error=True"
                assert "error" in _json["payload"], 'JSON payload has no "error" element'
                _error = _json["payload"]["error"]
                assert error == _error, f"Wrong error returned. expected: {error}, actual: {_error}"
            if payload is not None:
                for k, v in payload.items():
                    assert (
                        k in _json["payload"]
                    ), f"The Flux response payload {_json['payload']} does not contain {repr(k)}"
                    assert v == _json["payload"][k], (
                        f"The Flux response payload item {repr(k)} should be {repr(v)} "
                        f"but is {repr(_json['payload'][k])}"
                    )
            if assure_not_in_payload is not None:
                for key in assure_not_in_payload:
                    _assure_not_in_dict(_json["payload"], key)
            if meta is not None:
                for k, v in meta.items():
                    assert k in _json["meta"], f"The Flux response meta does not contain {repr(k)}"
                    assert (
                        v == _json["meta"][k]
                    ), f"The Flux response meta item {repr(k)} should be {repr(v)} but is {repr(_json['meta'][k])}"

        except (AssertionError, KeyError):
            if response.json:
                logger.info(
                    f"Test case got unexpected response ({response.status_code}):\n{pprint.pformat(response.json)}"
                )
            else:
                logger.info(f"Test case got unexpected response ({response.status_code}):\n{response.data}")
            raise

    def _check_nin_verified_ok(
        self,
        user: User,
        proofing_state: NinProofingState,
        number: str | None = None,
        created_by: str | None = None,
    ) -> None:
        if number is None and (self.test_user is not None and self.test_user.identities.nin):
            number = self.test_user.identities.nin.number

        created_by_str = created_by or proofing_state.nin.created_by

        assert user.identities.nin is not None
        assert user.identities.nin.number == number
        assert user.identities.nin.created_by == created_by_str
        assert user.identities.nin.verified_by == proofing_state.nin.created_by
        assert user.identities.nin.is_verified is True
        assert user.identities.nin.proofing_method is not None
        assert user.identities.nin.proofing_version is not None

        _log = getattr(self.app, "proofing_log")
        assert isinstance(_log, ProofingLog)
        assert _log.db_count() == 1

    def _check_nin_not_verified(self, user: User, number: str | None = None, created_by: str | None = None) -> None:
        if number is None and (self.test_user is not None and self.test_user.identities.nin):
            number = self.test_user.identities.nin.number

        assert user.identities.nin is not None
        assert user.identities.nin.number == number
        if created_by:
            assert user.identities.nin.created_by == created_by
        assert user.identities.nin.is_verified is False

        _log = getattr(self.app, "proofing_log")
        assert isinstance(_log, ProofingLog)
        assert _log.db_count() == 0


class CSRFTestClient(FlaskClient):
    # Add the custom csrf headers to every call to post
    def post(self, *args: Any, **kwargs: Any) -> TestResponse:
        """
        Adds the custom csrf headers as long as not initiated with custom_csrf_headers=False.

        This could also be done with updating FlaskClient.environ_base with the below header keys but
        that makes it harder to override per call to post.
        """
        assert isinstance(self.application, EduIDBaseApp)
        _conf = getattr(self.application, "conf")
        assert isinstance(_conf, EduIDBaseAppConfig)

        test_host = f"{_conf.flask.preferred_url_scheme}://{_conf.flask.server_name}"
        csrf_headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Referer": test_host,
            "X-Forwarded-Host": _conf.flask.server_name,
        }
        if kwargs.pop("custom_csrf_headers", True):
            if "headers" in kwargs:
                kwargs["headers"].update(csrf_headers)
            else:
                kwargs["headers"] = csrf_headers

        return super().post(*args, **kwargs)

    def get(self, *args: Any, **kwargs: Any) -> TestResponse:
        return super().get(*args, **kwargs)

    @contextmanager
    def session_transaction(self, *args: Any, **kwargs: Any) -> Generator[EduidSession, None, None]:
        """
        Get typed session in tests
        """
        with super().session_transaction(*args, **kwargs) as sess:
            assert isinstance(sess, EduidSession)
            yield sess
