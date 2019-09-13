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

from __future__ import absolute_import

import os
import sys
import traceback
from contextlib import contextmanager
from copy import deepcopy
from unittest import TestCase

from typing import Dict, Any

from flask.testing import FlaskClient

from eduid_common.session import EduidSession
from eduid_common.session.testing import RedisTemporaryInstance
from eduid_common.config.testing import EtcdTemporaryInstance
from eduid_common.config.workers import AmConfig
from eduid_common.config.base import FlaskConfig
from eduid_userdb import User
from eduid_userdb.db import BaseDB
from eduid_userdb.testing import MongoTemporaryInstance
from eduid_userdb.data_samples import NEW_USER_EXAMPLE, NEW_UNVERIFIED_USER_EXAMPLE, NEW_COMPLETED_SIGNUP_USER_EXAMPLE


TEST_CONFIG = {
    'DEBUG': True,
    'TESTING': True,
    'SECRET_KEY': 'mysecretkey',
    'SESSION_COOKIE_NAME': 'sessid',
    'SESSION_COOKIE_DOMAIN': 'test.localhost',
    'SESSION_COOKIE_PATH': '/',
    'SESSION_COOKIE_HTTPONLY': False,
    'SESSION_COOKIE_SECURE': False,
    'PERMANENT_SESSION_LIFETIME': '60',
    'SERVER_NAME': 'test.localhost',
    'PROPAGATE_EXCEPTIONS': True,
    'PRESERVE_CONTEXT_ON_EXCEPTION': True,
    'TRAP_HTTP_EXCEPTIONS': True,
    'TRAP_BAD_REQUEST_ERRORS': True,
    'PREFERRED_URL_SCHEME': 'http',
    'JSON_AS_ASCII': False,
    'JSON_SORT_KEYS': True,
    'JSONIFY_PRETTYPRINT_REGULAR': True,
    'MONGO_URI': 'mongodb://localhost',
    'REDIS_HOST': 'localhost',
    'REDIS_PORT': '6379',
    'REDIS_DB': '0',
    'REDIS_SENTINEL_HOSTS': '',
    'REDIS_SENTINEL_SERVICE_NAME': '',
    'TOKEN_SERVICE_URL': 'http://test.localhost/',
}

class APIMockedUserDB(object):

    test_users: Dict[str, Any] = {}

    def __init__(self, _patches):
        pass

    def all_userdocs(self):
        for user in self.test_users.values():
            yield deepcopy(user)


_standard_test_users = {
    'hubba-bubba': NEW_USER_EXAMPLE,
    'hubba-baar': NEW_UNVERIFIED_USER_EXAMPLE,
    'hubba-fooo': NEW_COMPLETED_SIGNUP_USER_EXAMPLE,
}


class EduidAPITestCase(MongoTestCase):
    """
    Base Test case for eduID APIs.

    See the `load_app` and `update_config` methods below before subclassing.
    """

    # This concept with a class variable is broken - doesn't provide isolation between tests.
    # Do what we can and initialise it empty here, and then fill it in __init__.
    MockedUserDB = APIMockedUserDB

    def setUp(self, init_am=True, users=None, copy_user_to_private=False,
            am_settings=None):
        super(MongoTestCase, self).setUp()
        self.MockedUserDB.test_users = {}
        if users is None:
            users = ['hubba-bubba']
        for this in users:
            self.MockedUserDB.test_users[this] = _standard_test_users.get(this)

        # get rid of the class variable self.user from MongoTestCase - class variables does
        # not provide proper isolation between tests
        self.user = None
        # Initialize some convenience variables on self based on the first user in `users'
        self.test_user_data = _standard_test_users.get(users[0])
        self.test_user = User(data=self.test_user_data)

        self.tmp_db = MongoTemporaryInstance.get_instance()

        if init_am:
            celery_settings = {
                    'broker_transport': 'memory',
                    'broker_url': 'memory://',
                    'task_eager_propagates': True,
                    'task_always_eager': True,
                    'result_backend': 'cache',
                    'cache_backend': 'memory',
                    }
            # Be sure to NOT tell AttributeManager about the temporary mongodb instance.
            # If we do, one or more plugins may open DB connections that never gets closed.
            mongo_uri = None
            if am_settings:
                want_mongo_uri = am_settings.pop('WANT_MONGO_URI', False)
                if want_mongo_uri:
                    mongo_uri = self.tmp_db.uri
            else:
                am_settings = {}
            am_settings['celery'] = celery_settings
            am_settings['mongo_uri'] = mongo_uri
            self.am_settings = AmConfig(**am_settings)
            # initialize eduid_am without requiring config in etcd
            import eduid_am
            celery = eduid_am.init_app(self.am_settings.celery)
            import eduid_am.worker
            eduid_am.worker.worker_config = self.am_settings
            logger.debug('Initialized AM with config:\n{!r}'.format(self.am_settings))

            self.am = eduid_am.get_attribute_manager(celery)
        self.amdb = UserDB(self.tmp_db.uri, 'eduid_am')

        mongo_settings = {
            'mongo_replicaset': None,
            'mongo_uri': self.tmp_db.uri,
        }
        self.settings = FlaskSettings(**mongo_settings)

        # Set up test users in the MongoDB. Read the users from MockedUserDB, which might
        # be overridden by subclasses.
        _foo_userdb = self.MockedUserDB(self.mock_users_patches)
        for userdoc in _foo_userdb.all_userdocs():
            this = deepcopy(userdoc)  # deep-copy to not have side effects between tests
            user = User(data=this)
            self.amdb.save(user, check_sync=False, old_format=userdb_use_old_format)

        self.redis_instance = RedisTemporaryInstance.get_instance()
        self.etcd_instance = EtcdTemporaryInstance.get_instance()
        config = deepcopy(TEST_CONFIG)
        config['REDIS_PORT'] = str(self.redis_instance.port)
        config['MONGO_URI'] = self.tmp_db.uri
        if init_am:
            # 'CELERY' is the key used in workers, and 'CELERY_CONFIG' is used in webapps.
            # self.am_settings is initialized by the super-class MongoTestCase.
            #
            # We need to copy this data from am_settings to config, because AM will be
            # re-initialized in load_app() below.
            config['CELERY_CONFIG'] = self.am_settings['CELERY']
            if self.am_settings.get('ACTION_PLUGINS'):
                config['ACTION_PLUGINS'] = self.am_settings['ACTION_PLUGINS']
        config = self.update_config(config)

        os.environ.update({'ETCD_PORT': str(self.etcd_instance.port)})
        self.app = self.load_app(config)
        self.app.test_client_class = CSRFTestClient
        self.browser = self.app.test_client()

        # Helper constants
        self.content_type_json = 'application/json'

        if copy_user_to_private:
            data = self.test_user.to_dict()
            self.app.private_userdb.save(self.app.private_userdb.UserClass(data=data),
                                         check_sync=False)

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
            #time.sleep(5)
        super(EduidAPITestCase, self).tearDown()
        # XXX reset redis

    def load_app(self, config):
        """
        Method that must be implemented by any subclass, where the
        flask app must be imported and returned.
        This is so we can set  the test configuration in environment variables
        before the flask app loads its config from a file.
        """
        msg = ('Classes extending EduidAPITestCase must provide a method '
               'where they import the flask app and return it.')
        raise NotImplementedError(msg)

    def update_config(self, config):
        """
        Method that can be overriden by any subclass,
        where it can add configuration specific for that API
        before loading the app.

        :param config: original configuration
        :type config: dict

        :return: the updated configuration
        :rtype: dict
        """
        return config

    @contextmanager
    def session_cookie(self, client, eppn, server_name='localhost'):
        with client.session_transaction() as sess:
            sess['user_eppn'] = eppn
            sess['user_is_logged_in'] = True
        client.set_cookie(server_name, key=self.app.config.session_cookie_name, value=sess._session.token)
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
        user = User(data=central_user_dict)
        user.modified_ts = modified_ts
        self.app.central_userdb.save(user)
        return True


class CSRFTestClient(FlaskClient):

    # Add the custom csrf headers to every call to post
    def post(self, *args, **kw):
        """
        Adds the custom csrf headers as long as not initiated with custom_csrf_headers=False.

        This could also be done with updating FlaskClient.environ_base with the below header keys but
        that makes it harder to override per call to post.
        """
        test_host = '{}://{}'.format(self.application.config.preferred_url_scheme,
                                     self.application.config.server_name)
        csrf_headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': test_host,
            'X-Forwarded-Host': self.application.config.server_name
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
