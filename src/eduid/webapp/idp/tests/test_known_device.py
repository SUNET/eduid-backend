import unittest
from datetime import timedelta
from uuid import UUID

import nacl.encoding
import nacl.secret
import nacl.utils
from bson import ObjectId
from nacl.secret import SecretBox

from eduid.common.misc.timeutil import utc_now
from eduid.webapp.idp.app import IdPApp
from eduid.webapp.idp.known_device import BrowserDeviceInfo, KnownDevice, KnownDeviceData, KnownDeviceId
from eduid.webapp.idp.tests.test_api import IdPAPITests


class TestBrowserDeviceInfo(unittest.TestCase):
    app_secret_box = SecretBox(
        nacl.encoding.URLSafeBase64Encoder.decode(b"TfRW-RFFk-8MFAXkOpBEfa1p9aObAavTiEGGX1P96og=")
    )

    nonce = nacl.encoding.Base64Encoder.decode(b"Z/37ehIJx2HfvxzhSctc5qTm0ZO66u4+")

    from_browser = (
        "8MOF0Zln2b1fpO1xFgR046w19rbYT_L9YDRYdU3yOI1lk-a4KMrKegTHgqGqkShNJkLZtQs53RUZD7IJu70ofrNn5Cadixd"
        "-aK8015Gjc8Yx0tTfVlBjS4K1pETE4sJq_O1JDDSPESzxA2ZpIMiS4XyWwP2wcn477dpg"
    )

    def test_new(self) -> None:
        first = BrowserDeviceInfo.new(app_secret_box=self.app_secret_box)
        second = BrowserDeviceInfo.new(app_secret_box=self.app_secret_box)
        assert first != second

        assert UUID(first.state_id) != UUID(second.state_id)

        assert first.shared != second.shared

    def test_parse(self) -> None:
        """Parse the string we would have gotten from the browser local storage"""
        first = BrowserDeviceInfo.from_public(self.from_browser, app_secret_box=self.app_secret_box)
        assert first.state_id == "bac35b64-955a-4fed-b96d-f076e6dd5cd5"
        assert first.shared == self.from_browser

    def test_secretbox(self) -> None:
        """Test the secretbox that will be used to encrypt the database contents"""

        # Initialise a BrowserDeviceInfo from the data that could have been stored in the browsers local storage.
        first = BrowserDeviceInfo.from_public(self.from_browser, app_secret_box=self.app_secret_box)

        # Validate that the secret box was set up using the expected secret key. Use it to encrypt/decrypt something.

        plain = b"test"
        test_encrypt = first.secret_box.encrypt(plain, nonce=self.nonce, encoder=nacl.encoding.URLSafeBase64Encoder)
        assert test_encrypt == b"Z_37ehIJx2HfvxzhSctc5qTm0ZO66u4-bj791OIlMJ9RWE3RtCgvi63WRL0="
        assert first.secret_box.decrypt(test_encrypt, encoder=nacl.encoding.URLSafeBase64Encoder) == plain

    def test_plaintext_v1(self) -> None:
        """Validate that the encrypted data is formatted correctly for v1"""
        decrypted = self.app_secret_box.decrypt(self.from_browser.encode(), encoder=nacl.encoding.URLSafeBase64Encoder)

        # check if the version matches the one we know how to parse
        assert decrypted.startswith(b"1|")

        # no extra b'' in the string for example
        assert decrypted == b"1|bac35b64-955a-4fed-b96d-f076e6dd5cd5|Q8MAaH/CApoZniM5iFVovifBrsyCr6zmLhlW9H7aLA0="

        _v, state_id, private_key = decrypted.decode().split("|")
        # check that it is a valid UUID
        assert UUID(state_id) == UUID("bac35b64-955a-4fed-b96d-f076e6dd5cd5")
        # check that the private_key is of the expected size for use as a secret box key
        assert len(nacl.encoding.Base64Encoder.decode(private_key.encode())) == nacl.secret.SecretBox.KEY_SIZE

    def test_str(self) -> None:
        """Ensure string representation doesn't disclose the secret key"""
        first = BrowserDeviceInfo.from_public(self.from_browser, app_secret_box=self.app_secret_box)
        assert str(first) == "<BrowserDeviceInfo: public[8]='8MOF0Zln', state_id[8]='bac35b64'>"


class TestKnownDevice(unittest.TestCase):
    app_secret_box = SecretBox(
        nacl.encoding.URLSafeBase64Encoder.decode(b"TfRW-RFFk-8MFAXkOpBEfa1p9aObAavTiEGGX1P96og=")
    )

    from_browser = (
        "8MOF0Zln2b1fpO1xFgR046w19rbYT_L9YDRYdU3yOI1lk-a4KMrKegTHgqGqkShNJkLZtQs53RUZD7IJu70ofrNn5Cadixd"
        "-aK8015Gjc8Yx0tTfVlBjS4K1pETE4sJq_O1JDDSPESzxA2ZpIMiS4XyWwP2wcn477dpg"
    )

    def test_encrypt_decrypt(self) -> None:
        data = KnownDeviceData(eppn="hubba-bubba", ip_address="127.1.2.3", user_agent="testing")
        now = utc_now()
        obj_id = ObjectId("6216608c39402aa8abf74a9d")
        first = KnownDevice(data=data, expires_at=now, last_used=now, state_id=KnownDeviceId("test-id"), _id=obj_id)
        browser_info = BrowserDeviceInfo.from_public(self.from_browser, app_secret_box=self.app_secret_box)
        first_dict = first.to_dict(from_browser=browser_info)

        encrypted_data = first_dict.pop("data")
        assert first_dict == {
            "expires_at": now,
            "last_used": now,
            "_id": ObjectId("6216608c39402aa8abf74a9d"),
            "state_id": "test-id",
        }
        # we can only test the type and length - the nonce will be different each time so the data changes
        assert isinstance(encrypted_data, bytes)
        assert len(encrypted_data) == 172

        # restore first_dict and try parsing it
        first_dict["data"] = encrypted_data

        second = KnownDevice.from_dict(first_dict, from_browser=browser_info)
        assert first.model_dump() == second.model_dump()

        # verify the random nonce will produce different output for each encryption
        assert first_dict != first.to_dict(from_browser=browser_info)


class TestIdPUserDb(IdPAPITests):
    def test_adding_new_known_device(self) -> None:
        assert isinstance(self.app, IdPApp)
        browser_info = self.app.known_device_db.create_new_state()
        first = self.app.known_device_db.get_state_by_browser_info(from_browser=browser_info)
        assert first
        assert first.data.eppn is None

        first.data.eppn = "hubba-bubba"
        self.app.known_device_db.save(first, from_browser=browser_info, ttl=timedelta(hours=1))

        second = self.app.known_device_db.get_state_by_browser_info(from_browser=browser_info)
        assert second
        assert second.data.eppn == "hubba-bubba"
