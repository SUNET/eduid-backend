#
# Copyright (c) 2012, 2013 NORDUnet A/S
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
# Author : Fredrik Thulin <fredrik@thulin.net>
#

import hmac
import os
import stat
from abc import ABC
from typing import Any, Dict, Mapping

from binascii import unhexlify
from hashlib import sha1

import yaml

import pyhsm


class VCCSHasher(ABC):
    def __init__(self, lock):
        self.lock = lock

    def unlock(self, password: str) -> None:
        raise NotImplementedError('Subclass should implement unlock')

    def info(self) -> Any:
        raise NotImplementedError('Subclass should implement info')

    def hmac_sha1(self, _key_handle, _data):
        raise NotImplementedError('Subclass should implement safe_hmac_sha1')

    def unsafe_hmac_sha1(self, _key_handle, _data):
        raise NotImplementedError('Subclass should implement hmac_sha1')

    def load_temp_key(self, _nonce, _key_handle, _aead):
        raise NotImplementedError('Subclass should implement load_temp_key')

    def safe_random(self, _byte_count):
        raise NotImplementedError('Subclass should implement safe_random')

    async def lock_acquire(self):
        return await self.lock.acquire()

    async def lock_release(self):
        return self.lock.release()


class VCCSYHSMHasher(VCCSHasher):
    def __init__(self, device, lock, debug=False):
        VCCSHasher.__init__(self, lock)
        self._yhsm = pyhsm.base.YHSM(device, debug)

    def unlock(self, password: str) -> None:
        """ Unlock YubiHSM on startup. The password is supposed to be hex encoded. """
        self._yhsm.unlock(unhexlify(password))

    def info(self) -> Any:
        return self._yhsm.info()

    async def hmac_sha1(self, key_handle: int, data: bytes) -> bytes:
        """
        Perform HMAC-SHA-1 operation using YubiHSM.

        Acquires a lock first if a lock instance was given at creation time.
        """
        await self.lock_acquire()
        try:
            return self.unsafe_hmac_sha1(key_handle, data)
        finally:
            await self.lock_release()

    def unsafe_hmac_sha1(self, key_handle: int, data: bytes) -> bytes:
        if key_handle is None:
            key_handle = pyhsm.defines.YSM_TEMP_KEY_HANDLE
        return self._yhsm.hmac_sha1(key_handle, data).get_hash()

    def load_temp_key(self, nonce, key_handle, aead):
        return self._yhsm.load_temp_key(nonce, key_handle, aead)

    async def safe_random(self, byte_count: int) -> bytes:
        """
        Generate random bytes using both YubiHSM random function and host OS.

        Acquires a lock first if a lock instance was given at creation time.
        """
        from_os = os.urandom(byte_count)
        await self.lock_acquire()
        try:
            from_hsm = self._yhsm.random(byte_count)
            xored = bytes([a ^ b for (a, b) in zip(from_hsm, from_os)])
            return xored
        finally:
            await self.lock_release()


class VCCSSoftHasher(VCCSHasher):

    """
    Hasher implementation without any real extra security benefits
    (except perhaps separating HMAC keys from credential store).
    """

    def __init__(self, keys: Mapping[int, str], lock, debug=False):
        VCCSHasher.__init__(self, lock)
        self.debug = debug
        # Covert keys from strings to bytes when loading
        self.keys: Dict[int, bytes] = {}
        for k,v in keys.items():
            self.keys[k] = unhexlify(v)

    def unlock(self, password: str) -> None:
        return None

    def info(self) -> Any:
        return f'key handles loaded: {list(self.keys.keys())}'

    async def hmac_sha1(self, key_handle, data):
        """
        Perform HMAC-SHA-1 operation using YubiHSM.

        Acquires a lock first if a lock instance was given at creation time.
        """
        await self.lock_acquire()
        try:
            return self.unsafe_hmac_sha1(key_handle, data)
        finally:
            await self.lock_release()

    def unsafe_hmac_sha1(self, key_handle, data):
        if key_handle is None:
            key_handle = 'TEMP_KEY'
        hmac_key = self.keys[key_handle]
        return hmac.new(hmac_key, msg=data, digestmod=sha1).digest()

    def load_temp_key(self, nonce, key_handle, aead):
        pt = pyhsm.soft_hsm.aesCCM(self.keys[key_handle], key_handle, nonce, aead, decrypt=True)
        self.keys['TEMP_KEY'] = pt[:-4]  # skip the last four bytes which are permission bits
        return True

    async def safe_random(self, byte_count):
        """
        Generate random bytes from urandom.
        """
        return os.urandom(byte_count)


class NoOpLock:
    """
    A No-op lock class, to avoid a lot of "if self.lock:" in code using locks.
    """

    def __init__(self):
        pass

    async def acquire(self):
        pass

    async def release(self):
        pass


def hasher_from_string(name: str, lock=None, debug=False):
    """
    Create a hasher instance from a name. Name can currently only be a
    name of a YubiHSM device, such as '/dev/ttyACM0'.

    An optional lock is passed in as an argument, to keep this module
    unaware of if threading is being used, and how. If a lock instance
    is given, it will be lock.acquire()'d and lock.release()'d when
    hashers hash.

    The lock must be reentrant to support OATH.
    """
    if not lock:
        lock = NoOpLock()
    if name.startswith('soft_hasher:'):
        fn = name.split(':')[1]
        with open(fn) as fd:
            data = yaml.safe_load(fd)
            return VCCSSoftHasher(keys=data['key_handles'], lock=lock)
    try:
        mode = os.stat(name).st_mode
        if stat.S_ISCHR(mode):
            return VCCSYHSMHasher(name, lock, debug)
        raise ValueError(f'Not a character device : {name}')
    except OSError:
        raise ValueError(f'Unknown hasher {repr(name)}')
