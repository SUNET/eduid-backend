import unittest

import pytest
from pydantic import ValidationError

import eduid.userdb.element
import eduid.userdb.exceptions
from eduid.common.testing_base import normalised_data
from eduid.userdb.orcid import OidcAuthorization, OidcIdToken, Orcid

__author__ = "lundberg"

token_response = {
    "access_token": "b8b8ca5d-b233-4d49-830a-ede934c626d3",
    "expires_in": 631138518,
    "id_token": {
        "at_hash": "hVBHwPjPNgJH5f87ez8h0w",
        "aud": ["APP_ID"],
        "auth_time": 1526389879,
        "exp": 1526392540,
        "family_name": "Testsson",
        "given_name": "Testarn",
        "iat": 1526391940,
        "iss": "https://op.example.org",
        "jti": "4a721a4b-301a-492b-950a-1b4a83d30149",
        "sub": "subject_identifier",
        "nonce": "a_nonce_token",
    },
    "name": "Testarn Testsson",
    "orcid": "user_orcid",
    "refresh_token": "a110e7d2-4968-42d4-a91d-f379b55a0e60",
    "scope": "openid",
    "token_type": "bearer",
}


class TestOrcid(unittest.TestCase):
    maxDiff = None

    def test_id_token(self) -> None:
        assert isinstance(token_response["id_token"], dict)
        id_token_data = token_response["id_token"]
        id_token_data["created_by"] = "test"
        id_token_1 = OidcIdToken.from_dict(id_token_data)
        id_token_2 = OidcIdToken(
            iss=id_token_data["iss"],
            sub=id_token_data["sub"],
            aud=id_token_data["aud"],
            exp=id_token_data["exp"],
            iat=id_token_data["iat"],
            nonce=id_token_data["nonce"],
            auth_time=id_token_data["auth_time"],
            created_by="test",
        )

        self.assertIsInstance(id_token_1, OidcIdToken)
        self.assertIsInstance(id_token_1.to_dict(), dict)
        self.assertEqual(id_token_1.key, id_token_2.key)

        dict_1 = id_token_1.to_dict()
        dict_2 = id_token_2.to_dict()

        del dict_2["created_ts"]
        del dict_2["modified_ts"]

        assert dict_1 == dict_2

        with self.assertRaises(eduid.userdb.exceptions.UserDBValueError):
            OidcIdToken.from_dict(None)  # type: ignore[arg-type]

    def test_oidc_authz(self) -> None:
        assert isinstance(token_response["id_token"], dict)
        id_token_data = token_response["id_token"]
        id_token_data["created_by"] = "test"
        id_token = OidcIdToken.from_dict(token_response["id_token"])

        token_response["created_by"] = "test"
        oidc_authz_1 = OidcAuthorization.from_dict(token_response)
        oidc_authz_2 = OidcAuthorization(
            access_token=token_response["access_token"],
            token_type=token_response["token_type"],
            id_token=id_token,
            expires_in=token_response["expires_in"],
            refresh_token=token_response["refresh_token"],
            created_by="test",
        )

        self.assertIsInstance(oidc_authz_1, OidcAuthorization)
        self.assertIsInstance(oidc_authz_1.to_dict(), dict)
        self.assertEqual(oidc_authz_1.key, oidc_authz_2.key)

        dict_1 = oidc_authz_1.to_dict()
        dict_2 = oidc_authz_2.to_dict()

        del dict_2["created_ts"]
        del dict_2["modified_ts"]

        assert dict_1 == dict_2

        with self.assertRaises(eduid.userdb.exceptions.UserDBValueError):
            OidcAuthorization.from_dict(None)  # type: ignore[arg-type]

    def test_orcid(self) -> None:
        assert isinstance(token_response["id_token"], dict)
        token_response["id_token"]["created_by"] = "test"
        token_response["created_by"] = "test"
        oidc_authz = OidcAuthorization.from_dict(token_response)
        orcid_1 = Orcid(
            id="https://op.example.org/user_orcid", oidc_authz=oidc_authz, created_by="test", is_verified=True
        )
        orcid_2 = Orcid.from_dict(data=orcid_1.to_dict())

        self.assertIsInstance(orcid_1, Orcid)
        self.assertIsInstance(orcid_1.to_dict(), dict)
        self.assertEqual(orcid_1.key, orcid_2.key)
        self.assertEqual(orcid_1.id, orcid_2.id)
        self.assertEqual(orcid_1.id, orcid_2.key)
        self.assertEqual(orcid_1.oidc_authz.key, orcid_2.oidc_authz.key)
        self.assertEqual(orcid_1.oidc_authz.id_token.key, orcid_2.oidc_authz.id_token.key)

        dict_1 = orcid_1.to_dict()
        dict_2 = orcid_2.to_dict()

        assert dict_1 == dict_2

        data = orcid_1.to_dict()
        data["unknown_key"] = "test"

        with pytest.raises(ValidationError) as exc_info:
            Orcid.from_dict(data)
        assert normalised_data(exc_info.value.errors(), exclude_keys=["url"]) == [
            {
                "input": "test",
                "loc": ["unknown_key"],
                "msg": "Extra inputs are not permitted",
                "type": "extra_forbidden",
            }
        ], f"Wrong error message: {normalised_data(exc_info.value.errors(), exclude_keys=['url'])}"

        with pytest.raises(eduid.userdb.exceptions.UserDBValueError):
            Orcid.from_dict(None)  # type: ignore[arg-type]
