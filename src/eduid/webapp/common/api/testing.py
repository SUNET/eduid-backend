#
# Copyright (c) 2016 NORDUnet A/S
# Copyright (c) 2018 SUNET
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
import logging
import logging.config
import pprint
import sys
import traceback
from contextlib import contextmanager
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Mapping, Optional

from flask.testing import FlaskClient
from flask.wrappers import Response

from eduid.common.config.base import RedisConfig
from eduid.common.rpc.msg_relay import NavetData
from eduid.common.testing_base import CommonTestCase
from eduid.userdb import User
from eduid.userdb.db import BaseDB
from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.proofing.state import NinProofingState
from eduid.userdb.testing import MongoTemporaryInstance
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.session import EduidSession
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
    "token_service_url": "http://test.localhost/",
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
            "eduid.webapp.common.session": {"level": "INFO"},
            "eduid.userdb.userdb.extra_debug": {"level": "INFO"},
            "eduid.userdb.db.extra_debug": {"level": "INFO"},
            "eduid.userdb": {"level": "INFO"},
        }
    },
}


class EduidAPITestCase(CommonTestCase):
    """
    Base Test case for eduID APIs.

    See the `load_app` and `update_config` methods below before subclassing.
    """

    def setUp(self, *args, users: Optional[List[str]] = None, copy_user_to_private: bool = False, **kwargs):
        # test users
        if users is None:
            users = ["hubba-bubba"]

        _users = UserFixtures()
        _standard_test_users = {
            "hubba-bubba": _users.new_user_example,
            "hubba-baar": _users.new_unverified_user_example,
            "hubba-fooo": _users.new_completed_signup_user_example,
        }

        # Make a list of User object to be saved to the new temporary mongodb instance
        am_users = [_standard_test_users[x] for x in users]

        super().setUp(*args, am_users=am_users, **kwargs)

        self.user: Optional[User] = None  # type: ignore

        # Load the user from the database so that it can be saved there again in tests
        _test_user = self.amdb.get_user_by_eppn(users[0])
        assert _test_user is not None
        # Initialize some convenience variables on self based on the first user in `users'
        self.test_user = _test_user
        self.test_user_data = self.test_user.to_dict()

        # Set up Redis for shared sessions
        self.redis_instance = RedisTemporaryInstance.get_instance()
        # settings
        config = deepcopy(TEST_CONFIG)
        self.settings = self.update_config(config)
        self.settings["redis_config"] = RedisConfig(host="localhost", port=self.redis_instance.port)
        assert isinstance(self.tmp_db, MongoTemporaryInstance)  # please mypy
        self.settings["mongo_uri"] = self.tmp_db.uri

        self.app = self.load_app(self.settings)
        if not getattr(self, "browser", False):
            self.app.test_client_class = CSRFTestClient
            self.browser = self.app.test_client()

        # Helper constants
        self.content_type_json = "application/json"

        if copy_user_to_private:
            data = self.test_user.to_dict()
            logging.info(f"Copying test-user {self.test_user} to private_userdb {self.app.private_userdb}")
            self.app.private_userdb.save(self.app.private_userdb.user_from_dict(data=data))

    def tearDown(self):
        try:
            # Reset anything that looks like a BaseDB, for the next test class.
            # Also explicitly close the connections to the database, or we will
            # run out of file descriptors in some settings
            for this in vars(self.app).values():
                if isinstance(this, BaseDB):
                    this._drop_whole_collection()
                    this.close()
        except Exception as exc:
            sys.stderr.write("Exception in tearDown: {!s}\n{!r}\n".format(exc, exc))
            traceback.print_exc()
            # time.sleep(5)
        super(CommonTestCase, self).tearDown()
        # XXX reset redis

    def load_app(self, config):
        """
        Method that must be implemented by any subclass, where the
        flask app must be imported and returned.
        This is so we can set  the test configuration in environment variables
        before the flask app loads its config from a file.
        """
        raise NotImplementedError(
            "Classes extending EduidAPITestCase must provide a method where they import the flask app and return it."
        )

    def update_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
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
        self, client: Any, eppn: Optional[str], server_name: str = "localhost", logged_in: bool = True, **kwargs
    ):
        with client.session_transaction(**kwargs) as sess:
            if eppn is not None:
                sess.common.eppn = eppn
                sess.common.is_logged_in = logged_in
            client.set_cookie(server_name, key=self.app.conf.flask.session_cookie_name, value=sess.meta.cookie_val)
        yield client

    @contextmanager
    def session_cookie_anon(self, client, server_name="localhost", **kwargs):
        with self.session_cookie(client=client, eppn=None, server_name=server_name, **kwargs) as _client:
            yield _client

    def request_user_sync(self, private_user: User, app_name_override: Optional[str] = None) -> bool:
        """
        Updates the central db user with data from the private db user.

        :param private_user: User to save in central db
        :type private_user: Private subclass of eduid_db.user.User
        :return: True
        """
        logger.info(f"Saving user {private_user} to central userdb using test-request_user_sync() method")

        central_user = self.app.central_userdb.get_user_by_id(private_user.user_id)
        private_user_dict = private_user.to_dict()
        # fix signup_user data
        if "proofing_reference" in private_user_dict:
            del private_user_dict["proofing_reference"]

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

        # Restore metadata that is necessary for the consistency checks in the save() function
        user.modified_ts = central_user.modified_ts
        user.meta.modified_ts = central_user.meta.modified_ts
        user.meta.version = central_user.meta.version
        user.meta.is_in_database = True

        # Make the new version in AM match the one in the private userdb
        # user.meta.new_version = lambda: private_user.new_version

        self.app.central_userdb.save(user)
        return True

    @staticmethod
    def _get_all_navet_data():
        return NavetData.parse_obj(MessageSender.get_devel_all_navet_data())

    def _check_error_response(
        self,
        response: Response,
        type_: Optional[str],
        msg: Optional[TranslatableMsg] = None,
        error: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ):
        """Check that a call to the API failed in the data validation stage."""
        return self._check_api_response(response, 200, type_=type_, message=msg, error=error, payload=payload)

    def _check_success_response(
        self,
        response: Response,
        type_: Optional[str],
        msg: Optional[TranslatableMsg] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ):
        """
        Check the message returned from an eduID webapp endpoint.
        """
        return self._check_api_response(response, 200, type_=type_, message=msg, payload=payload)

    @staticmethod
    def _check_api_response(
        response: Response,
        status: int,
        type_: Optional[str],
        message: Optional[TranslatableMsg] = None,
        error: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
        assure_not_in_payload: Optional[Iterable[str]] = None,
    ):
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

        def _assure_not_in_dict(d: Mapping[str, Any], unwanted_key: str):
            assert unwanted_key not in d, f"Key {unwanted_key} should not be in payload, but it is: {payload}"
            for k2, v2 in d.items():
                if isinstance(v2, dict):
                    _assure_not_in_dict(v2, unwanted_key)

        try:
            assert status == response.status_code, f"The HTTP response code was {response.status_code} not {status}"
            if type_ is not None:
                assert (
                    type_ == response.json["type"]
                ), f'Wrong response type. expected: {type_}, actual: {response.json["type"]}'
            assert "payload" in response.json, 'JSON body has no "payload" element'
            if message is not None:
                assert "message" in response.json["payload"], 'JSON payload has no "message" element'
                _message_value = response.json["payload"]["message"]
                assert (
                    message.value == _message_value
                ), f"Wrong message returned. expected: {message.value}, actual: {_message_value}"
            if error is not None:
                assert response.json["error"] is True, "The Flux response was supposed to have error=True"
                assert "error" in response.json["payload"], 'JSON payload has no "error" element'
                _error = response.json["payload"]["error"]
                assert error == _error, f"Wrong error returned. expected: {error}, actual: {_error}"
            if payload is not None:
                for k, v in payload.items():
                    assert k in response.json["payload"], f"The Flux response payload does not contain {repr(k)}"
                    assert (
                        v == response.json["payload"][k]
                    ), f"The Flux response payload item {repr(k)} is not {repr(v)}"
            if assure_not_in_payload is not None:
                for key in assure_not_in_payload:
                    _assure_not_in_dict(response.json["payload"], key)

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
        number: Optional[str] = None,
        created_by: Optional[str] = None,
    ):
        if number is None and (self.test_user is not None and self.test_user.identities.nin):
            number = self.test_user.identities.nin.number

        created_by_str = created_by or proofing_state.nin.created_by

        assert user.identities.nin is not None
        assert user.identities.nin.number == number
        assert user.identities.nin.created_by == created_by_str
        assert user.identities.nin.verified_by == proofing_state.nin.created_by
        assert user.identities.nin.is_verified is True
        assert self.app.proofing_log.db_count() == 1

    def _check_nin_not_verified(self, user: User, number: Optional[str] = None, created_by: Optional[str] = None):
        if number is None and (self.test_user is not None and self.test_user.identities.nin):
            number = self.test_user.identities.nin.number

        assert user.identities.nin is not None
        assert user.identities.nin.number == number
        if created_by:
            assert user.identities.nin.created_by == created_by
        assert user.identities.nin.is_verified is False
        assert self.app.proofing_log.db_count() == 0


class CSRFTestClient(FlaskClient):

    # Add the custom csrf headers to every call to post
    def post(self, *args, **kw):
        """
        Adds the custom csrf headers as long as not initiated with custom_csrf_headers=False.

        This could also be done with updating FlaskClient.environ_base with the below header keys but
        that makes it harder to override per call to post.
        """
        test_host = "{}://{}".format(
            self.application.conf.flask.preferred_url_scheme, self.application.conf.flask.server_name
        )
        csrf_headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Referer": test_host,
            "X-Forwarded-Host": self.application.conf.flask.server_name,
        }
        if kw.pop("custom_csrf_headers", True):
            if "headers" in kw:
                kw["headers"].update(csrf_headers)
            else:
                kw["headers"] = csrf_headers

        return super(CSRFTestClient, self).post(*args, **kw)

    #  The return type of a generator function should be "Generator" or one of its supertypes
    #  Argument 1 to "contextmanager" has incompatible type "Callable[[CSRFTestClient, VarArg(Any), KwArg(Any)],
    #  EduidSession]"; expected "Callable[..., Iterator[<nothing>]]"
    #  Return type of "session_transaction" incompatible with supertype "FlaskClient"
    #  "None" has no attribute "__enter__"
    #  "None" has no attribute "__exit__"
    @contextmanager  # type: ignore
    def session_transaction(self, *args, **kwargs) -> EduidSession:  # type: ignore
        """
        Get typed session in tests
        Use # type: ignore to keep mypy happy
        """
        with super().session_transaction(*args, **kwargs) as sess:  # type: ignore
            yield sess
