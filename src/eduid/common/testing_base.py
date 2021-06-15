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

from eduid.common.logging import LocalContext, make_dictConfig
from eduid.userdb.testing import MongoTestCase

logger = logging.getLogger(__name__)


class CommonTestCase(MongoTestCase):
    """ Base Test case for eduID webapps and workers """

    def setUp(self, *args, **kwargs):
        """
        set up tests
        """
        # Set up provisional logging to capture logs from test setup too
        self._init_logging()

        if 'EDUID_CONFIG_YAML' not in os.environ:
            os.environ['EDUID_CONFIG_YAML'] = 'YAML_CONFIG_NOT_USED'

        super().setUp(*args, **kwargs)

    def _init_logging(self):
        local_context = LocalContext(
            app_debug=True,
            app_name='testing',
            format='{asctime} | {levelname:7} |             | {name:35} | {message}',
            level='DEBUG',
            relative_time=True,
        )
        logging_config = make_dictConfig(local_context)
        logging.config.dictConfig(logging_config)
