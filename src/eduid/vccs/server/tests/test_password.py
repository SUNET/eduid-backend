import unittest
from unittest.mock import AsyncMock, MagicMock

import pytest

from eduid.vccs.server.db import KDF, CredType, PasswordCredential, Status, Version
from eduid.vccs.server.password import calculate_cred_hash


class TestCalculateCredHash(unittest.IsolatedAsyncioTestCase):
    def _make_cred(self, version: Version, key_label: str | None = None) -> PasswordCredential:
        return PasswordCredential(
            credential_id="test_cred_id",
            derived_key="",
            iterations=1,
            kdf=KDF.PBKDF2_HMAC_SHA512,
            key_handle=8192,
            salt="aa" * 16,
            status=Status.ACTIVE,
            type=CredType.PASSWORD,
            version=version,
            key_label=key_label,
        )

    async def test_v1_uses_hmac_sha1(self) -> None:
        cred = self._make_cred(Version.NDNv1)
        hasher = MagicMock()
        hasher.hmac_sha1 = AsyncMock(return_value=b"\x00" * 20)
        hasher.hmac_sha256 = AsyncMock(return_value=b"\x00" * 32)
        kdf = MagicMock()
        kdf.pbkdf2_hmac_sha512 = MagicMock(return_value=b"\xab" * 64)

        await calculate_cred_hash(user_id="test_user", H1="aa" * 16, cred=cred, hasher=hasher, kdf=kdf)

        hasher.hmac_sha1.assert_called_once()
        hasher.hmac_sha256.assert_not_called()

    async def test_v2_uses_hmac_sha256(self) -> None:
        cred = self._make_cred(Version.NDNv2, key_label="test-key")
        hasher = MagicMock()
        hasher.hmac_sha1 = AsyncMock(return_value=b"\x00" * 20)
        new_hasher = MagicMock()
        new_hasher.hmac_sha256 = AsyncMock(return_value=b"\x00" * 32)
        kdf = MagicMock()
        kdf.pbkdf2_hmac_sha512 = MagicMock(return_value=b"\xab" * 64)

        await calculate_cred_hash(
            user_id="test_user", H1="aa" * 16, cred=cred, hasher=hasher, kdf=kdf, new_hasher=new_hasher
        )

        new_hasher.hmac_sha256.assert_called_once_with("test-key", kdf.pbkdf2_hmac_sha512.return_value)
        hasher.hmac_sha1.assert_not_called()
        hasher.hmac_sha256.assert_not_called()

    async def test_v2_without_key_label_raises(self) -> None:
        cred = self._make_cred(Version.NDNv2, key_label=None)
        hasher = MagicMock()
        kdf = MagicMock()
        kdf.pbkdf2_hmac_sha512 = MagicMock(return_value=b"\xab" * 64)

        with pytest.raises(ValueError, match="key_label"):
            await calculate_cred_hash(user_id="test_user", H1="aa" * 16, cred=cred, hasher=hasher, kdf=kdf)

    async def test_v1_and_v2_produce_different_hashes(self) -> None:
        """V1 and V2 should produce different H2 values for the same input."""
        hasher = MagicMock()
        hasher.hmac_sha1 = AsyncMock(return_value=b"\x01" * 20)
        new_hasher = MagicMock()
        new_hasher.hmac_sha256 = AsyncMock(return_value=b"\x02" * 32)
        kdf = MagicMock()
        kdf.pbkdf2_hmac_sha512 = MagicMock(side_effect=[b"\xab" * 64, b"\xcd" * 64, b"\xab" * 64, b"\xef" * 64])

        cred_v1 = self._make_cred(Version.NDNv1)
        h2_v1 = await calculate_cred_hash(user_id="test_user", H1="aa" * 16, cred=cred_v1, hasher=hasher, kdf=kdf)

        cred_v2 = self._make_cred(Version.NDNv2, key_label="test-key")
        h2_v2 = await calculate_cred_hash(
            user_id="test_user", H1="aa" * 16, cred=cred_v2, hasher=hasher, kdf=kdf, new_hasher=new_hasher
        )

        assert h2_v1 != h2_v2

    async def test_v2_uses_new_hasher(self) -> None:
        """NDNv2 should use new_hasher.hmac_sha256, not the legacy hasher."""
        cred = self._make_cred(Version.NDNv2, key_label="test-key")
        hasher = MagicMock()
        hasher.hmac_sha1 = AsyncMock(return_value=b"\x00" * 20)
        hasher.hmac_sha256 = AsyncMock(return_value=b"\x00" * 32)
        new_hasher = MagicMock()
        new_hasher.hmac_sha256 = AsyncMock(return_value=b"\xff" * 32)
        kdf = MagicMock()
        kdf.pbkdf2_hmac_sha512 = MagicMock(return_value=b"\xab" * 64)

        await calculate_cred_hash(
            user_id="test_user", H1="aa" * 16, cred=cred, hasher=hasher, kdf=kdf, new_hasher=new_hasher
        )

        # new_hasher should be used, not the legacy hasher
        new_hasher.hmac_sha256.assert_called_once()
        hasher.hmac_sha256.assert_not_called()
        hasher.hmac_sha1.assert_not_called()

    async def test_v2_without_new_hasher_raises(self) -> None:
        """NDNv2 without new_hasher should raise RuntimeError."""
        cred = self._make_cred(Version.NDNv2, key_label="test-key")
        hasher = MagicMock()
        hasher.hmac_sha1 = AsyncMock(return_value=b"\x00" * 20)
        kdf = MagicMock()
        kdf.pbkdf2_hmac_sha512 = MagicMock(return_value=b"\xab" * 64)

        with pytest.raises(RuntimeError, match="new_hasher"):
            await calculate_cred_hash(user_id="test_user", H1="aa" * 16, cred=cred, hasher=hasher, kdf=kdf)

    async def test_v1_ignores_new_hasher(self) -> None:
        """NDNv1 should use hasher.hmac_sha1, ignoring new_hasher entirely."""
        cred = self._make_cred(Version.NDNv1)
        hasher = MagicMock()
        hasher.hmac_sha1 = AsyncMock(return_value=b"\x00" * 20)
        new_hasher = MagicMock()
        new_hasher.hmac_sha256 = AsyncMock(return_value=b"\xff" * 32)
        new_hasher.hmac_sha1 = AsyncMock(return_value=b"\xff" * 20)
        kdf = MagicMock()
        kdf.pbkdf2_hmac_sha512 = MagicMock(return_value=b"\xab" * 64)

        await calculate_cred_hash(
            user_id="test_user", H1="aa" * 16, cred=cred, hasher=hasher, kdf=kdf, new_hasher=new_hasher
        )

        # Legacy hasher should be used for v1
        hasher.hmac_sha1.assert_called_once()
        # new_hasher should not be touched
        new_hasher.hmac_sha256.assert_not_called()
        new_hasher.hmac_sha1.assert_not_called()


class TestAddCredsVersion(unittest.TestCase):
    def test_request_factor_accepts_version(self) -> None:
        from eduid.vccs.server.factors import RequestFactor

        factor = RequestFactor(H1="aabb", credential_id="test", type="password", version="NDNv2")
        assert factor.version == "NDNv2"

    def test_request_factor_defaults_to_v1(self) -> None:
        from eduid.vccs.server.factors import RequestFactor

        factor = RequestFactor(H1="aabb", credential_id="test", type="password")
        assert factor.version == "NDNv1"
