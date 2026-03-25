import datetime
from hashlib import sha256

import pytest

from eduid.userdb.credentials import CredentialList, CredentialProofingMethod, Webauthn

__author__ = "lundberg"

_one_dict = {
    "app_id": "unit test",
    "keyhandle": "firstWebauthnElement",
    "credential_data": "bar",
}
_two_dict = {
    "app_id": "unit test",
    "keyhandle": "secondWebauthnElement",
    "credential_data": "bar",
}
_three_dict = {
    "app_id": "unit test",
    "keyhandle": "thirdWebauthnElement",
    "credential_data": "bar",
}


def _keyid(key: dict[str, str]) -> str:
    return "sha256:" + sha256(key["keyhandle"].encode("utf-8") + key["credential_data"].encode("utf-8")).hexdigest()


class TestWebauthn:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        self.empty = CredentialList()
        self.one = CredentialList.from_list_of_dicts([_one_dict])
        self.two = CredentialList.from_list_of_dicts([_one_dict, _two_dict])
        self.three = CredentialList.from_list_of_dicts([_one_dict, _two_dict, _three_dict])

    def test_key(self) -> None:
        """
        Test that the 'key' property (used by CredentialList) works for the credential.
        """
        this = self.one.find(_keyid(_one_dict))
        assert this
        assert isinstance(this, Webauthn)
        assert this.key == _keyid({"keyhandle": this.keyhandle, "credential_data": this.credential_data})

    def test_parse_cycle(self) -> None:
        """
        Tests that we output something we parsed back into the same thing we output.
        """
        for this in [self.one, self.two, self.three]:
            this_dict = this.to_list_of_dicts()
            assert CredentialList.from_list_of_dicts(this_dict).to_list_of_dicts() == this.to_list_of_dicts()

    def test_created_by(self) -> None:
        this = self.three.find(_keyid(_three_dict))
        assert this
        this.created_by = "unit test"
        assert this.created_by == "unit test"

    def test_created_ts(self) -> None:
        this = self.three.find(_keyid(_three_dict))
        assert this
        assert isinstance(this.created_ts, datetime.datetime)

    def test_proofing_method(self) -> None:
        this = self.three.find(_keyid(_three_dict))
        assert this
        this.proofing_method = CredentialProofingMethod.SWAMID_AL2_MFA_HI
        assert this.proofing_method == CredentialProofingMethod.SWAMID_AL2_MFA_HI
        this.proofing_method = CredentialProofingMethod.SWAMID_AL3_MFA
        assert this.proofing_method == CredentialProofingMethod.SWAMID_AL3_MFA
        this.proofing_method = None
        assert this.proofing_method is None

    def test_proofing_version(self) -> None:
        this = self.three.find(_keyid(_three_dict))
        assert this
        this.proofing_version = "TEST"
        assert this.proofing_version == "TEST"
        this.proofing_version = "TEST2"
        assert this.proofing_version == "TEST2"
        this.proofing_version = None
        assert this.proofing_version is None
