import hmac
import os
import stat
from abc import ABC, abstractmethod
from asyncio.locks import Lock
from binascii import unhexlify
from hashlib import sha1, sha256
from typing import Literal

import pkcs11
import pyhsm
from hsmkey import HSMConfig, SessionPool
from pkcs11 import KeyType, Mechanism, ObjectClass

from eduid.vccs.server.config import HSMKeyConfig, SoftHasherConfig, YHSMConfig


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

    @abstractmethod
    def unlock(self) -> None:
        raise NotImplementedError("Subclass should implement unlock")

    @abstractmethod
    def info(self) -> str | bytes | None:
        raise NotImplementedError("Subclass should implement info")

    @abstractmethod
    async def hmac_sha1(self, key_handle: int, data: bytes) -> bytes:
        raise NotImplementedError("Subclass should implement hmac_sha1")

    @abstractmethod
    def unsafe_hmac_sha1(self, key_handle: int, data: bytes) -> bytes:
        raise NotImplementedError("Subclass should implement unsafe_hmac_sha1")

    @abstractmethod
    async def hmac_sha256(self, key_label: str, data: bytes) -> bytes:
        raise NotImplementedError("Subclass should implement hmac_sha256")

    @abstractmethod
    def unsafe_hmac_sha256(self, key_label: str, data: bytes) -> bytes:
        raise NotImplementedError("Subclass should implement unsafe_hmac_sha256")

    @abstractmethod
    async def safe_random(self, byte_count: int) -> bytes:
        raise NotImplementedError("Subclass should implement safe_random")

    async def lock_acquire(self) -> Literal[True] | None:
        return await self.lock.acquire()

    def lock_release(self) -> None:
        self.lock.release()


class VCCSYHSMHasher(VCCSHasher):
    def __init__(self, config: YHSMConfig, lock: Lock | NoOpLock, debug: bool = False) -> None:
        try:
            mode = os.stat(config.device).st_mode
            if not stat.S_ISCHR(mode):
                raise ValueError(f"Not a character device: {config.device}")
        except OSError as e:
            raise ValueError(f"Unknown hasher {repr(config.device)}") from e

        super().__init__(lock)
        self._yhsm = pyhsm.base.YHSM(config.device, debug)
        self._unlock_password = config.unlock_password

    def unlock(self) -> None:
        """Unlock YubiHSM on startup. The password is supposed to be hex encoded."""
        if self._unlock_password:  # do not try to unlock with None or empty string
            self._yhsm.unlock(unhexlify(self._unlock_password))

    def info(self) -> str:
        # pyhsm.base.YHSM.info() returns bytes(?)
        ret: bytes = self._yhsm.info()
        if isinstance(ret, bytes):
            return ret.decode()
        else:
            return ret

    async def hmac_sha1(self, key_handle: int, data: bytes) -> bytes:
        """
        Perform HMAC-SHA-1 operation using YubiHSM.

        Acquires a lock first if a lock instance was given at creation time.
        """
        await self.lock_acquire()
        try:
            return self.unsafe_hmac_sha1(key_handle, data)
        finally:
            self.lock_release()

    def unsafe_hmac_sha1(self, key_handle: int, data: bytes) -> bytes:
        return self._yhsm.hmac_sha1(key_handle, data).get_hash()

    async def hmac_sha256(self, key_label: str, data: bytes) -> bytes:
        raise NotImplementedError("hmac sha256 not supported by YubiHSM")

    def unsafe_hmac_sha256(self, key_label: str, data: bytes) -> bytes:
        raise NotImplementedError("hmac sha256 not supported by YubiHSM")

    async def safe_random(self, byte_count: int) -> bytes:
        """
        Generate random bytes using both YubiHSM random function and host OS.

        Acquires a lock first if a lock instance was given at creation time.
        """
        from_os = os.urandom(byte_count)
        await self.lock_acquire()
        try:
            from_hsm = self._yhsm.random(byte_count)
            xored = bytes([a ^ b for (a, b) in zip(from_hsm, from_os, strict=True)])
            return xored
        finally:
            self.lock_release()


class VCCSSoftHasher(VCCSHasher):
    """
    Hasher implementation without any real extra security benefits
    (except perhaps separating HMAC keys from credential store).
    """

    def __init__(self, config: SoftHasherConfig, lock: Lock | NoOpLock, debug: bool = False) -> None:
        super().__init__(lock)
        self.debug = debug
        # Covert keys from strings to bytes when loading
        self.keys: dict[int | str, bytes] = {}
        for k, v in config.key_handles.items():
            self.keys[k] = unhexlify(v)

    def unlock(self) -> None:
        return None

    def info(self) -> str:
        return f"key handles loaded: {list(self.keys.keys())}"

    async def hmac_sha1(self, key_handle: int, data: bytes) -> bytes:
        """
        Perform HMAC-SHA-1 operation using Python stdlib hmac module.

        Acquires a lock first if a lock instance was given at creation time.
        """
        await self.lock_acquire()
        try:
            return self.unsafe_hmac_sha1(key_handle, data)
        finally:
            self.lock_release()

    def unsafe_hmac_sha1(self, key_handle: int, data: bytes) -> bytes:
        hmac_key = self.keys[key_handle]
        return hmac.new(hmac_key, msg=data, digestmod=sha1).digest()

    async def hmac_sha256(self, key_label: str, data: bytes) -> bytes:
        """
        Perform HMAC-SHA-256 operation using Python stdlib hmac module.

        Acquires a lock first if a lock instance was given at creation time.
        """
        await self.lock_acquire()
        try:
            return self.unsafe_hmac_sha256(key_label, data)
        finally:
            self.lock_release()

    def unsafe_hmac_sha256(self, key_label: str, data: bytes) -> bytes:
        hmac_key = self.keys[key_label]
        return hmac.new(hmac_key, msg=data, digestmod=sha256).digest()

    async def safe_random(self, byte_count: int) -> bytes:
        """
        Generate random bytes from urandom.
        """
        return os.urandom(byte_count)


class VCCSHSMKeyHasher(VCCSHasher):
    """
    Hasher implementation using the hsmkey module for PKCS#11 HSM access.

    This provides a generic PKCS#11 interface that can work with various HSMs
    including SoftHSM2 (for testing), YubiHSM 2, and other PKCS#11-compatible devices.

    Key identification supports both:
    - Integer key handles (as CKA_ID bytes, for backward compatibility)
    - String key labels (as CKA_LABEL)
    """

    def __init__(
        self,
        config: HSMKeyConfig,
        lock: Lock | NoOpLock,
        debug: bool = False,
    ) -> None:
        """
        Initialize the HSMKey-based hasher.

        :param config: HSMConfig with module_path, token_label, and user_pin
        :param lock: Lock for thread-safe HSM access
        :param debug: Enable debug logging
        """
        super().__init__(lock)
        self.debug = debug
        hsm_config = HSMConfig(
            module_path=config.module_path,
            token_label=config.token_label,
            user_pin=config.user_pin,
            so_pin=config.so_pin,
        )
        self._config = hsm_config

        self._pool = SessionPool(
            module_path=config.module_path,
            token_label=config.token_label,
            user_pin=config.user_pin,
            so_pin=config.so_pin,
        )

    def unlock(self) -> None:
        """
        Unlock is handled via user_pin in config for PKCS#11.

        This method exists for API compatibility but PKCS#11 authentication
        is done when opening sessions with the PIN provided in config.
        """
        # PKCS#11 uses PIN authentication when opening sessions
        # The PIN is already configured via HSMConfig.user_pin
        return None

    def info(self) -> str:
        """Return information about the HSM connection."""
        return f"hsmkey PKCS#11: module={self._config.module_path}, token={self._config.token_label}"

    @staticmethod
    def _get_hmac_key(
        session: pkcs11.Session,
        key_handle: int | None = None,
        key_label: str | None = None,
        key_type: KeyType = KeyType.GENERIC_SECRET,
    ) -> pkcs11.Key:
        """
        Get an HMAC key from the HSM.

        :param session: Open PKCS#11 session
        :param key_handle: Integer key handle (used as CKA_ID)
        :param key_label: String key label (used as CKA_LABEL)
        :param key_type: PKCS#11 key type (default: KeyType.GENERIC_SECRET)
        :returns: PKCS#11 secret key object
        :raises RuntimeError: If no key identifier provided or key not found
        """
        if key_handle is None and key_label is None:
            raise RuntimeError("No key handle or label provided, and no temp key loaded")

        try:
            # Build search attributes
            attrs: dict[str, bytes | str | KeyType | ObjectClass] = {
                "key_type": key_type,
                "object_class": ObjectClass.SECRET_KEY,
            }
            if key_handle is not None:
                # Convert integer key handle to bytes for CKA_ID
                attrs["id"] = key_handle.to_bytes((key_handle.bit_length() + 7) // 8 or 1, byteorder="big")
            if key_label is not None:
                attrs["label"] = key_label

            return session.get_key(**attrs)
        except pkcs11.NoSuchKey as e:
            raise RuntimeError(f"HMAC key not found: handle={key_handle}, label={key_label}") from e

    async def hmac_sha1(self, key_handle: int, data: bytes) -> bytes:
        """
        Perform HMAC-SHA-1 operation using PKCS#11 HSM.

        Acquires a lock first if a lock instance was given at creation time.

        :param key_handle: Integer key handle (CKA_ID) or None to use temp key
        :param data: Data to HMAC
        :returns: 20-byte HMAC-SHA-1 digest
        """
        await self.lock_acquire()
        try:
            return self.unsafe_hmac_sha1(key_handle, data)
        finally:
            self.lock_release()

    def unsafe_hmac_sha1(self, key_handle: int, data: bytes) -> bytes:
        """
        Perform HMAC-SHA-1 without acquiring lock.

        :param key_handle: Integer key handle (CKA_ID) or None to use temp key
        :param data: Data to HMAC
        :returns: 20-byte HMAC-SHA-1 digest
        """
        with self._pool.session() as session:
            key = self._get_hmac_key(session, key_handle)
            # Use the key's sign method with SHA_1_HMAC mechanism
            return key.sign(data, mechanism=Mechanism.SHA_1_HMAC)

    async def hmac_sha256(self, key_label: str, data: bytes) -> bytes:
        """
        Perform HMAC-SHA-256 operation using PKCS#11 HSM.

        Acquires a lock first if a lock instance was given at creation time.

        :param key_label: String key label (CKA_LABEL)
        :param data: Data to HMAC
        :returns: 32-byte HMAC-SHA-256 digest
        """
        await self.lock_acquire()
        try:
            return self.unsafe_hmac_sha256(key_label, data)
        finally:
            self.lock_release()

    def unsafe_hmac_sha256(self, key_label: str, data: bytes) -> bytes:
        """
        Perform HMAC-SHA-256 without acquiring lock.

        :param key_label: String key label (CKA_LABEL)
        :param data: Data to HMAC
        :returns: 32-byte HMAC-SHA-256 digest
        """
        with self._pool.session() as session:
            key = self._get_hmac_key(session, key_label=key_label)
            # Use the key's sign method with SHA256_HMAC mechanism
            return key.sign(data, mechanism=Mechanism.SHA256_HMAC)

    async def safe_random(self, byte_count: int) -> bytes:
        """
        Generate random bytes using both PKCS#11 HSM and host OS.

        XORs random bytes from the HSM with os.urandom() for defense in depth.

        Acquires a lock first if a lock instance was given at creation time.

        :param byte_count: Number of random bytes to generate
        :returns: Random bytes
        """
        from_os = os.urandom(byte_count)
        await self.lock_acquire()
        try:
            with self._pool.session() as session:
                # generate_random takes bits, not bytes
                from_hsm = session.generate_random(byte_count * 8)
                xored = bytes([a ^ b for (a, b) in zip(from_hsm, from_os, strict=True)])
                return xored
        finally:
            self.lock_release()


def load_hasher(
    config: YHSMConfig | HSMKeyConfig | SoftHasherConfig, lock: Lock | NoOpLock | None = None, debug: bool = False
) -> VCCSSoftHasher | VCCSYHSMHasher | VCCSHSMKeyHasher:
    """
    Create a hasher instance from config.

    Supported configs:
    - SoftHasherConfig - Software hasher with HMAC keys in config
    - HSMKeyConfig - PKCS#11 hasher using hsmkey module
    - YHSMConfig - YubiHSM 1 via pyhsm

    An optional lock is passed in as an argument, to keep this module
    unaware of if threading is being used, and how. If a lock instance
    is given, it will be lock.acquire()'d and lock.release()'d when
    hashers hash.

    :param config: Hasher config
    :param lock: Optional lock for thread-safe access
    :param debug: Enable debug mode
    :returns: Configured hasher instance
    """
    if not lock:
        lock = NoOpLock()

    match config:
        case SoftHasherConfig():
            return VCCSSoftHasher(config=config, lock=lock, debug=debug)
        case HSMKeyConfig():
            return VCCSHSMKeyHasher(config=config, lock=lock, debug=debug)
        case YHSMConfig():
            return VCCSYHSMHasher(config=config, lock=lock, debug=debug)
        case _:
            raise ValueError(f"Unknown hasher {repr(config)}")
