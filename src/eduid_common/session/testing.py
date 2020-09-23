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
from typing import Optional, Sequence

import redis

from eduid_common.misc.temp_instance import EduidTemporaryInstance

logger = logging.getLogger(__name__)


class RedisTemporaryInstance(EduidTemporaryInstance):
    """Singleton to manage a temporary Redis instance

    Use this for testing purpose only. The instance is automatically destroyed
    at the end of the program.

    """

    @property
    def command(self) -> Sequence[str]:
        return [
            'docker',
            'run',
            '--rm',
            '-p',
            '{!s}:6379'.format(self.port),
            '-v',
            '{!s}:/data'.format(self.tmpdir),
            '-e',
            'extra_args=--daemonize no --bind 0.0.0.0',
            'docker.sunet.se/eduid/redis:latest',
        ]

    def setup_conn(self) -> bool:
        try:
            host, port, db = self.get_params()
            _conn = redis.Redis(host, port, db)
            _conn.set('dummy', 'dummy')
            self._conn = _conn
        except redis.exceptions.ConnectionError:
            return False
        return True

    @property
    def conn(self) -> redis.Redis:
        if self._conn is None:
            raise RuntimeError('Missing temporary Redis instance')
        return self._conn

    def get_params(self):
        """
        Convenience function to get Redis connection parameters for the temporary database.

        :return: Host, port and database
        """
        return 'localhost', self.port, 0
