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
import os
from typing import Any, Dict, List, Optional

from eduid_userdb import User
from eduid_userdb.testing import MongoTemporaryInstance, MongoTestCase

from eduid_common.api.logging import LocalContext, make_dictConfig
from eduid_common.config.testing import EtcdTemporaryInstance
from eduid_common.config.workers import AmConfig

logger = logging.getLogger(__name__)


class CommonTestCase(MongoTestCase):
    """ Base Test case for eduID webapps and workers """

    def setUp(self, **kwargs):
        """
        set up tests
        """
        # Set up provisional logging to capture logs from test setup too
        self._init_logging()

        super().setUp(**kwargs)

        # Set up etcd
        self.etcd_instance = EtcdTemporaryInstance.get_instance()
        os.environ.update({'ETCD_PORT': str(self.etcd_instance.port)})

    def _init_logging(self):
        local_context = LocalContext(
            app_debug=True,
            app_name='testing',
            format='{asctime} | {levelname:7} | {name:35} | {message}',
            level='DEBUG',
            relative_time=True,
        )
        logging_config = make_dictConfig(local_context)
        logging.config.dictConfig(logging_config)


class WorkerTestCase(CommonTestCase):
    """
    Base Test case for eduID celery workers
    """

    def setUp(self, am_settings: Optional[Dict[str, Any]] = None, want_mongo_uri: bool = True, **kwargs):
        """
        set up tests
        """
        super().setUp(**kwargs)

        settings = {
            'app_name': 'testing',
            'celery': {
                'broker_transport': 'memory',
                'broker_url': 'memory://',
                'task_eager_propagates': True,
                'task_always_eager': True,
                'result_backend': 'cache',
                'cache_backend': 'memory',
            },
            # Be sure to NOT tell AttributeManager about the temporary mongodb instance.
            # If we do, one or more plugins may open DB connections that never gets closed.
            'mongo_uri': None,
        }

        if am_settings:
            settings.update(am_settings)
        if want_mongo_uri:
            assert isinstance(self.tmp_db, MongoTemporaryInstance)  # please mypy
            settings['mongo_uri'] = self.tmp_db.uri

        am_config = AmConfig(**settings)

        # initialize eduid_am without requiring config in etcd
        import eduid_am

        celery = eduid_am.init_app(am_config.celery)
        import eduid_am.worker

        eduid_am.worker.worker_config = am_config
        logger.debug(f'Initialized AM with config:\n{am_config}')

        self.am = eduid_am.get_attribute_manager(celery)
