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

import time
import atexit
import random
import subprocess

import etcd


class EtcdTemporaryInstance(object):
    """Singleton to manage a temporary Etcd instance

    Use this for testing purpose only. The instance is automatically destroyed
    at the end of the program.

    """
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
            atexit.register(cls._instance.shutdown)
        return cls._instance

    def __init__(self):
        self._port = random.randint(40000, 50000)
        self._process = subprocess.Popen(['docker', 'run', '--rm',
                                          '-p', '{!s}:2379'.format(self._port),
                                          'docker.sunet.se/library/etcd:v2.2.5',
                                          '-advertise-client-urls', 'http://${HostIP}:2379',
                                          '-listen-client-urls', 'http://0.0.0.0:2379'],
                                         stdout=open('/tmp/etcd-temp.log', 'wb'),
                                         stderr=subprocess.STDOUT)

        for i in range(10):
            time.sleep(0.2)
            try:
                self._conn = etcd.Client('localhost', self._port)
                self._conn.stats  # Check connection
            except etcd.EtcdConnectionFailed:
                continue
            else:
                break
        else:
            self.shutdown()
            assert False, 'Cannot connect to the etcd test instance'

    @property
    def conn(self):
        return self._conn

    @property
    def host(self):
        return self._conn.host

    @property
    def port(self):
        return self._port

    def shutdown(self):
        if self._process:
            self._process.terminate()
            self._process.wait()
            self._process = None
        if EtcdTemporaryInstance._instance == self:
            EtcdTemporaryInstance._instance = None
