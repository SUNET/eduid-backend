import hmac
import os
import stat
from abc import ABC
from asyncio.locks import Lock
from binascii import unhexlify
from collections.abc import Mapping
from hashlib import sha1
from typing import Literal

import pyhsm
import yaml


class NoOpLock:
    """
    A No-op lock class, to avoid a lot of "if self.lock:" in code using locks.
    """

    def __init__(self) -> None:
        pass

    async def acquire(self) -> None:
        pass

    async def release(self) -> None:
        pass


class VCCSHasher(ABC):
    def __init__(self, lock: Lock | NoOpLock) -> None:
        self.lock = lock

    def unlock(self, password: str) -> None:
        raise NotImplementedError("Subclass should implement unlock")

    def info(self) -> str | bytes | None:
        raise NotImplementedError("Subclass should implement info")

    async def hmac_sha1(self, key_handle: int | None, data: bytes) -> bytes:
        raise NotImplementedError("Subclass should implement safe_hmac_sha1")

    def unsafe_hmac_sha1(self, key_handle: int | None, data: bytes) -> bytes:
        raise NotImplementedError("Subclass should implement hmac_sha1")

    def load_temp_key(self, nonce: str, key_handle: int, aead: bytes) -> bool:
        raise NotImplementedError("Subclass should implement load_temp_key")

    async def safe_random(self, byte_count: int) -> bytes:
        raise NotImplementedError("Subclass should implement safe_random")

    async def lock_acquire(self) -> Literal[True] | None:
        return await self.lock.acquire()

    def lock_release(self) -> None:
        self.lock.release()


class VCCSYHSMHasher(VCCSHasher):
    def __init__(self, device: str, lock: Lock | NoOpLock, debug: bool = False) -> None:
        VCCSHasher.__init__(self, lock)
        self._yhsm = pyhsm.base.YHSM(device, debug)

    def unlock(self, password: str) -> None:
        """Unlock YubiHSM on startup. The password is supposed to be hex encoded."""
        self._yhsm.unlock(unhexlify(password))

    def info(self) -> str:
        # pyhsm.base.YHSM.info() returns bytes(?)
        ret: bytes = self._yhsm.info()
        if isinstance(ret, bytes):
            return ret.decode()
        else:
            return ret

    async def hmac_sha1(self, key_handle: int | None, data: bytes) -> bytes:
        """
        Perform HMAC-SHA-1 operation using YubiHSM.

        Acquires a lock first if a lock instance was given at creation time.
        """
        await self.lock_acquire()
        try:
            return self.unsafe_hmac_sha1(key_handle, data)
        finally:
            self.lock_release()

    def unsafe_hmac_sha1(self, key_handle: int | None, data: bytes) -> bytes:
        if key_handle is None:
            key_handle = pyhsm.defines.YSM_TEMP_KEY_HANDLE
        return self._yhsm.hmac_sha1(key_handle, data).get_hash()

    def load_temp_key(self, nonce: str, key_handle: int, aead: bytes) -> bool:
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
            self.lock_release()


class VCCSSoftHasher(VCCSHasher):
    """
    Hasher implementation without any real extra security benefits
    (except perhaps separating HMAC keys from credential store).
    """

    def __init__(self, keys: Mapping[int, str], lock: Lock | NoOpLock, debug: bool = False) -> None:
        super().__init__(lock)
        self.debug = debug
        # Covert keys from strings to bytes when loading
        self.keys: dict[int, bytes] = {}
        self._temp_key: bytes | None = None
        for k, v in keys.items():
            self.keys[k] = unhexlify(v)

    def unlock(self, password: str) -> None:
        return None

    def info(self) -> str:
        return f"key handles loaded: {list(self.keys.keys())}"

    async def hmac_sha1(self, key_handle: int | None, data: bytes) -> bytes:
        """
        Perform HMAC-SHA-1 operation using YubiHSM.

        Acquires a lock first if a lock instance was given at creation time.
        """
        await self.lock_acquire()
        try:
            return self.unsafe_hmac_sha1(key_handle, data)
        finally:
            self.lock_release()

    def unsafe_hmac_sha1(self, key_handle: int | None, data: bytes) -> bytes:
        if key_handle is None:
            if not self._temp_key:
                raise RuntimeError("No key handle provided, and no temp key loaded")
            hmac_key = self._temp_key
        else:
            hmac_key = self.keys[key_handle]
        return hmac.new(hmac_key, msg=data, digestmod=sha1).digest()

    def load_temp_key(self, nonce: str, key_handle: int, aead: bytes) -> bool:
        pt = pyhsm.soft_hsm.aesCCM(self.keys[key_handle], key_handle, nonce, aead, decrypt=True)
        self._temp_key = pt[:-4]  # skip the last four bytes which are permission bits
        return True

    async def safe_random(self, byte_count: int) -> bytes:
        """
        Generate random bytes from urandom.
        """
        return os.urandom(byte_count)


def hasher_from_string(
    name: str, lock: Lock | NoOpLock | None = None, debug: bool = False
) -> VCCSSoftHasher | VCCSYHSMHasher:
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
    if name.startswith("soft_hasher:"):
        fn = name.split(":")[1]
        with open(fn) as fd:
            data = yaml.safe_load(fd)
            return VCCSSoftHasher(keys=data["key_handles"], lock=lock)
    try:
        mode = os.stat(name).st_mode
        if stat.S_ISCHR(mode):
            return VCCSYHSMHasher(name, lock, debug)
        raise ValueError(f"Not a character device : {name}")
    except OSError:
        raise ValueError(f"Unknown hasher {repr(name)}")
