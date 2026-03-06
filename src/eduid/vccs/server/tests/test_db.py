import unittest

from bson import ObjectId

from eduid.vccs.server.db import PasswordCredential, Version


class TestCredential(unittest.TestCase):
    def setUp(self) -> None:
        self.data = {
            "_id": ObjectId("54042b7a9b3f2299bb9d5546"),
            "credential": {
                "status": "active",
                "derived_key": "65d27b345ceafe533c3314e021517a84be921fa545366a755d998d140bb6e596fd8"
                "7b61296a60eb8a17a1523350869ee97b581a1b75ba77b3d625d3281186fc5",
                "version": "NDNv1",
                "iterations": 50000,
                "key_handle": 8192,
                "salt": "d393c00d56d3c6f0fcf32421395427d2",
                "kdf": "PBKDF2-HMAC-SHA512",
                "type": "password",
                "credential_id": "54042b7aafce77049473096a",
            },
            "revision": 1,
        }

    def test_from_dict(self) -> None:
        cred = PasswordCredential.from_dict(self.data)
        assert cred.key_handle == 8192

    def test_to_dict_from_dict(self) -> None:
        cred1 = PasswordCredential.from_dict(self.data)
        cred2 = PasswordCredential.from_dict(cred1.to_dict())
        assert cred1.to_dict() == cred2.to_dict()
        assert cred2.to_dict() == self.data

    def test_from_dict_v2(self) -> None:
        data = {
            "_id": ObjectId("65042b7a9b3f2299bb9d5546"),
            "credential": {
                "status": "active",
                "derived_key": "aabbcc",
                "version": "NDNv2",
                "iterations": 50000,
                "key_handle": 8192,
                "key_label": "vccs-v2-hmac-key",
                "salt": "d393c00d56d3c6f0fcf32421395427d2",
                "kdf": "PBKDF2-HMAC-SHA512",
                "type": "password",
                "credential_id": "65042b7aafce77049473096a",
            },
            "revision": 1,
        }
        cred = PasswordCredential.from_dict(data)
        assert cred.version == Version.NDNv2
        assert cred.key_label == "vccs-v2-hmac-key"

    def test_to_dict_from_dict_v2(self) -> None:
        data = {
            "_id": ObjectId("65042b7a9b3f2299bb9d5546"),
            "credential": {
                "status": "active",
                "derived_key": "aabbcc",
                "version": "NDNv2",
                "iterations": 50000,
                "key_handle": 8192,
                "key_label": "vccs-v2-hmac-key",
                "salt": "d393c00d56d3c6f0fcf32421395427d2",
                "kdf": "PBKDF2-HMAC-SHA512",
                "type": "password",
                "credential_id": "65042b7aafce77049473096a",
            },
            "revision": 1,
        }
        cred1 = PasswordCredential.from_dict(data)
        cred2 = PasswordCredential.from_dict(cred1.to_dict())
        assert cred1.to_dict() == cred2.to_dict()
        assert cred2.to_dict() == data
