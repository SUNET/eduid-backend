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
from typing import Sequence

import etcd

from eduid.userdb.testing import EduidTemporaryInstance

logger = logging.getLogger(__name__)


class EtcdTemporaryInstance(EduidTemporaryInstance):
    """Singleton to manage a temporary Etcd instance

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
            '{!s}:2379'.format(self._port),
            'docker.sunet.se/library/etcd:v3.3.12',
            'etcd',
            '--advertise-client-urls',
            'http://0.0.0.0:2379',
            '--listen-client-urls',
            'http://0.0.0.0:2379',
        ]

    def setup_conn(self) -> bool:
        try:
            self._conn = etcd.Client('localhost', self.port)
            # Check connection
            if not self._conn.stats:
                raise etcd.EtcdConnectionFailed('No etcd stats')
        except etcd.EtcdConnectionFailed:
            return False
        return True

    @property
    def conn(self) -> etcd.Client:
        if self._conn is None:
            raise RuntimeError('Missing temporary etcd instance')
        return self._conn

    @property
    def host(self):
        return self._conn.host

    @property
    def port(self):
        return self._port

    def clear(self, key):
        try:
            self._conn.delete(key=key, recursive=True, dir=True)
        except etcd.EtcdKeyNotFound:
            pass
