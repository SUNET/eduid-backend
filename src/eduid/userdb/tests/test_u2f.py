import copy
import datetime
from hashlib import sha256
from unittest import TestCase

import pytest
from pydantic import ValidationError

from eduid.common.testing_base import normalised_data
from eduid.userdb.credentials import U2F, CredentialList, CredentialProofingMethod

__author__ = "lundberg"

# {'passwords': {
#    'id': password_id,                         # noqa: ERA001
#    'salt': salt,                              # noqa: ERA001
#    'source': 'signup',                        # noqa: ERA001
#    'created_ts': datetime.datetime.utcnow(),  # noqa: ERA001
# }}                                            # noqa: ERA001

_one_dict = {
    "version": "U2F_V2",
    "app_id": "unit test",
    "keyhandle": "firstU2FElement",
    "public_key": "foo",
}
_two_dict = {
    "version": "U2F_V2",
    "app_id": "unit test",
    "keyhandle": "secondU2FElement",
    "public_key": "foo",
}
_three_dict = {
    "version": "U2F_V2",
    "app_id": "unit test",
    "keyhandle": "thirdU2FElement",
    "public_key": "foo",
}


def _keyid(key: dict[str, str]):
    return "sha256:" + sha256(key["keyhandle"].encode("utf-8") + key["public_key"].encode("utf-8")).hexdigest()


class TestU2F(TestCase):
    def setUp(self) -> None:
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
        assert isinstance(this, U2F)
        self.assertEqual(
            this.key,
            _keyid(
                {
                    "keyhandle": this.keyhandle,
                    "public_key": this.public_key,
                }
            ),
        )

    def test_parse_cycle(self) -> None:
        """
        Tests that we output something we parsed back into the same thing we output.
        """
        for this in [self.one, self.two, self.three]:
            this_dict = this.to_list_of_dicts()
            self.assertEqual(CredentialList.from_list_of_dicts(this_dict).to_list_of_dicts(), this.to_list_of_dicts())

    def test_unknown_input_data(self) -> None:
        one = copy.deepcopy(_one_dict)
        one["foo"] = "bar"
        with pytest.raises(ValidationError) as exc_info:
            U2F.from_dict(one)
        assert normalised_data(exc_info.value.errors(), exclude_keys=["url"]) == [
            {
                "input": "bar",
                "loc": ["foo"],
                "msg": "Extra inputs are not permitted",
                "type": "extra_forbidden",
            }
        ], f"Wrong error message: {normalised_data(exc_info.value.errors(), exclude_keys=['url'])}"

    def test_created_by(self) -> None:
        this = self.three.find(_keyid(_three_dict))
        assert this
        this.created_by = "unit test"
        self.assertEqual(this.created_by, "unit test")

    def test_created_ts(self) -> None:
        this = self.three.find(_keyid(_three_dict))
        assert this
        self.assertIsInstance(this.created_ts, datetime.datetime)

    def test_proofing_method(self) -> None:
        this = self.three.find(_keyid(_three_dict))
        assert this
        this.proofing_method = CredentialProofingMethod.SWAMID_AL2_MFA_HI
        self.assertEqual(this.proofing_method, CredentialProofingMethod.SWAMID_AL2_MFA_HI)
        this.proofing_method = CredentialProofingMethod.SWAMID_AL3_MFA
        self.assertEqual(this.proofing_method, CredentialProofingMethod.SWAMID_AL3_MFA)
        this.proofing_method = None
        self.assertEqual(this.proofing_method, None)

    def test_proofing_version(self) -> None:
        this = self.three.find(_keyid(_three_dict))
        assert this
        this.proofing_version = "TEST"
        self.assertEqual(this.proofing_version, "TEST")
        this.proofing_version = "TEST2"
        self.assertEqual(this.proofing_version, "TEST2")
        this.proofing_version = None
        self.assertEqual(this.proofing_version, None)

    def test_swamid_al2_hi_to_swamid_al3_migration(self) -> None:
        this = self.three.find(_keyid(_three_dict))
        assert this
        this.proofing_method = CredentialProofingMethod.SWAMID_AL2_MFA_HI
        this.is_verified = True
        load_save_cred_list = CredentialList.from_list_of_dicts([this.to_dict()])
        load_save_cred = load_save_cred_list.find(_keyid(_three_dict))
        assert load_save_cred
        self.assertEqual(load_save_cred.proofing_method, CredentialProofingMethod.SWAMID_AL3_MFA)
