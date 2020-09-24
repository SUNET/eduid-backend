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
import json
import logging
import pprint
import sys
import traceback
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from flask import Response
from flask.testing import FlaskClient

from eduid_userdb import User
from eduid_userdb.db import BaseDB
from eduid_userdb.fixtures.users import new_completed_signup_user_example, new_unverified_user_example, new_user_example
from eduid_userdb.testing import AbstractMockedUserDB

from eduid_common.api.messages import TranslatableMsg
from eduid_common.api.testing_base import CommonTestCase
from eduid_common.session import EduidSession
from eduid_common.session.testing import RedisTemporaryInstance

logger = logging.getLogger(__name__)


TEST_CONFIG = {
    'debug': True,
    'testing': True,
    'secret_key': 'mysecretkey',
    'session_cookie_name': 'sessid',
    'session_cookie_domain': 'test.localhost',
    'session_cookie_path': '/',
    'session_cookie_httponly': False,
    'session_cookie_secure': False,
    'permanent_session_lifetime': 60,
    'server_name': 'test.localhost',
    'propagate_exceptions': True,
    'preserve_context_on_exception': True,
    'trap_http_exceptions': True,
    'trap_bad_request_errors': True,
    'preferred_url_scheme': 'http',
    'json_as_ascii': False,
    'json_sort_keys': True,
    'jsonify_prettyprint_regular': True,
    'mongo_uri': 'mongodb://localhost',
    'redis_host': 'localhost',
    'redis_port': 6379,
    'redis_db': 0,
    'redis_sentinel_hosts': '',
    'redis_sentinel_service_name': '',
    'token_service_url': 'http://test.localhost/',
}


_standard_test_users = {
    'hubba-bubba': new_user_example,
    'hubba-baar': new_unverified_user_example,
    'hubba-fooo': new_completed_signup_user_example,
}


class APIMockedUserDB(AbstractMockedUserDB):

    test_users: Dict[str, Any] = {}

    def __init__(self, _patches):
        pass


class EduidAPITestCase(CommonTestCase):
    """
    Base Test case for eduID APIs.

    See the `load_app` and `update_config` methods below before subclassing.
    """

    # This concept with a class variable is broken - doesn't provide isolation between tests.
    # Do what we can and initialise it empty here, and then fill it in __init__.
    MockedUserDB = APIMockedUserDB

    def setUp(
        self,
        init_am: bool = False,
        am_settings: Optional[Dict[str, Any]] = None,
        users: Optional[List[str]] = None,
        copy_user_to_private: bool = False,
    ):
        """
        set up tests
        """
        # test users
        self.MockedUserDB.test_users = {}
        if users is None:
            users = ['hubba-bubba']
        for this in users:
            _user = _standard_test_users.get(this)
            if _user is not None:
                self.MockedUserDB.test_users[this] = _user.to_dict()

        self.user = None  # type: ignore
        # Initialize some convenience variables on self based on the first user in `users'
        self.test_user_data = _standard_test_users[users[0]].to_dict()
        self.test_user = User.from_dict(self.test_user_data)

        super(EduidAPITestCase, self).setUp(init_am=init_am, am_settings=am_settings, users=users)
        # Set up Redis for shared sessions
        self.redis_instance = RedisTemporaryInstance.get_instance()
        # settings
        config = deepcopy(TEST_CONFIG)
        self.settings = self.update_config(config)
        self.settings['redis_port'] = str(self.redis_instance.port)
        self.settings['mongo_uri'] = self.tmp_db.uri
        # 'CELERY' is the key used in workers, and 'CELERY_CONFIG' is used in webapps.
        # self.am_settings is initialized by the super-class MongoTestCase.
        #
        # We need to copy this data from am_settings to config, because AM will be
        # re-initialized in load_app() below.
        self.settings['celery_config'] = self.am_settings['celery']

        settings = self.settings
        if not isinstance(settings, dict):
            settings = settings.to_dict()

        self.app = self.load_app(settings)
        if not getattr(self, 'browser', False):
            self.app.test_client_class = CSRFTestClient
            self.browser = self.app.test_client()

        # Helper constants
        self.content_type_json = 'application/json'

        if copy_user_to_private:
            data = self.test_user.to_dict()
            self.app.private_userdb.save(self.app.private_userdb.UserClass.from_dict(data=data), check_sync=False)

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
            'Classes extending EduidAPITestCase must provide a method where they import the flask app and return it.'
        )

    def update_config(self, config):
        """
        Method that can be overridden by any subclass,
        where it can add configuration specific for that API
        before loading the app.

        :param config: original configuration
        :type config: dict

        :return: the updated configuration
        :rtype: FlaskConfig
        """
        return config

    @contextmanager
    def session_cookie(self, client, eppn, server_name='localhost', **kwargs):
        with client.session_transaction(**kwargs) as sess:
            sess['user_eppn'] = eppn
            sess['user_is_logged_in'] = True
        client.set_cookie(server_name, key=self.app.config.session_cookie_name, value=sess._session.token.cookie_val)
        yield client

    @contextmanager
    def session_cookie_anon(self, client, server_name='localhost', **kwargs):
        with client.session_transaction(**kwargs) as sess:
            pass
        client.set_cookie(server_name, key=self.app.config.session_cookie_name, value=sess._session.token.cookie_val)
        yield client

    def request_user_sync(self, private_user):
        """
        Updates the central db user with data from the private db user.

        :param private_user: User to save in central db
        :type private_user: Private subclass of eduid_db.user.User
        :return: True
        :rtype: Boolean
        """
        user_id = str(private_user.user_id)
        central_user = self.app.central_userdb.get_user_by_id(user_id)
        modified_ts = central_user.modified_ts
        central_user_dict = central_user.to_dict()
        private_user_dict = private_user.to_dict()
        central_user_dict.update(private_user_dict)
        # Iterate over all top level keys and remove those missing
        for key in list(central_user_dict.keys()):
            if key not in private_user_dict:
                central_user_dict.pop(key, None)
        user = User.from_dict(data=central_user_dict)
        user.modified_ts = modified_ts
        self.app.central_userdb.save(user)
        return True

    def _check_error_response(
        self,
        response: Response,
        type_: str,
        msg: Optional[TranslatableMsg] = None,
        error: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ):
        """ Check that a call to the API failed in the data validation stage. """
        return self._check_api_response(response, 200, type_=type_, message=msg, error=error, payload=payload)

    def _check_success_response(
        self,
        response: Response,
        type_: str,
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
        type_: str,
        message: Optional[TranslatableMsg] = None,
        error: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
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
        try:
            assert status == response.status_code, f'The HTTP response code was {response.status_code} not {status}'
            assert (
                type_ == response.json['type']
            ), f'Wrong response type. expected: {type_}, actual: {response.json["type"]}'
            assert 'payload' in response.json, 'JSON body has no "payload" element'
            if message is not None:
                assert 'message' in response.json['payload'], 'JSON payload has no "message" element'
                _message_value = response.json['payload']['message']
                assert (
                    message.value == _message_value
                ), f'Wrong message returned. expected: {message.value}, actual: {_message_value}'
            if error is not None:
                assert response.json['error'] is True, 'The Flux response was supposed to have error=True'
                assert 'error' in response.json['payload'], 'JSON payload has no "error" element'
                _error = response.json['payload']['error']
                assert error == _error, f'Wrong error returned. expected: {error}, actual: {_error}'
            if payload is not None:
                for k, v in payload.items():
                    assert k in response.json['payload'], f'The Flux response payload does not contain {repr(k)}'
                    assert (
                        v == response.json['payload'][k]
                    ), f'The Flux response payload item {repr(k)} is not {repr(v)}'
        except (AssertionError, KeyError):
            if response.json:
                logger.info(
                    f'Test case got unexpected response ({response.status_code}):\n{pprint.pformat(response.json)}'
                )
            else:
                logger.info(f'Test case got unexpected response ({response.status_code}):\n{response.data}')
            raise


class CSRFTestClient(FlaskClient):

    # Add the custom csrf headers to every call to post
    def post(self, *args, **kw):
        """
        Adds the custom csrf headers as long as not initiated with custom_csrf_headers=False.

        This could also be done with updating FlaskClient.environ_base with the below header keys but
        that makes it harder to override per call to post.
        """
        test_host = '{}://{}'.format(self.application.config.preferred_url_scheme, self.application.config.server_name)
        csrf_headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': test_host,
            'X-Forwarded-Host': self.application.config.server_name,
        }
        if kw.pop('custom_csrf_headers', True):
            if 'headers' in kw:
                kw['headers'].update(csrf_headers)
            else:
                kw['headers'] = csrf_headers

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


def normalised_data(
    data: Union[Mapping[str, Any], Sequence[Mapping[str, Any]]]
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """ Utility function for normalising dicts (or list of dicts) before comparisons in test cases. """
    if isinstance(data, list):
        # Recurse into lists of dicts. mypy (correctly) says this recursion can in fact happen
        # more than once, so the result can be a list of list of dicts or whatever, but the return
        # type becomes too bloated with that in mind and the code becomes too inelegant when unrolling
        # this list comprehension into a for-loop checking types for something only intended to be used in test cases.
        # Hence the type: ignore.
        return sorted([_normalise_value(x) for x in data], key=_any_key)  # type: ignore
    elif isinstance(data, dict):
        # normalise all values found in the dict, returning a new dict (to not modify callers data)
        return {k: _normalise_value(v) for k, v in data.items()}
    raise TypeError('normalised_data not called on dict (or list of dicts)')


class SortEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return str(_normalise_value(obj))
        return json.JSONEncoder.default(self, obj)


def _any_key(value: Any):
    """ Helper function to be able to use sorted with key argument for everything """
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, cls=SortEncoder)  # Turn dict in to a string for sorting
    return value


def _normalise_value(data: Any) -> Any:
    if isinstance(data, dict) or isinstance(data, list):
        return normalised_data(data)
    elif isinstance(data, datetime):
        return data.replace(microsecond=0, tzinfo=None)
    return data
