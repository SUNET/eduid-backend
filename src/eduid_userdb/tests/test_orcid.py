# -*- coding: utf-8 -*-

from unittest import TestCase

import eduid_userdb.exceptions
import eduid_userdb.element
from eduid_userdb.orcid import Orcid, OidcAuthorization, OidcIdToken

__author__ = 'lundberg'

token_response = {
    "access_token": "b8b8ca5d-b233-4d49-830a-ede934c626d3",
    "expires_in": 631138518,
    "id_token": {
        "at_hash": "hVBHwPjPNgJH5f87ez8h0w",
        "aud": [
            "APP_ID"
        ],
        "auth_time": 1526389879,
        "exp": 1526392540,
        "family_name": "Testsson",
        "given_name": "Testarn",
        "iat": 1526391940,
        "iss": "https://op.example.org",
        "jti": "4a721a4b-301a-492b-950a-1b4a83d30149",
        "sub": "subject_identifier",
        "nonce": "a_nonce_token"
    },
    "name": "Testarn Testsson",
    "orcid": "user_orcid",
    "refresh_token": "a110e7d2-4968-42d4-a91d-f379b55a0e60",
    "scope": "openid",
    "token_type": "bearer"
}


class TestOrcid(TestCase):

    def test_id_token(self):
        id_token_data = token_response['id_token']
        id_token_data['created_ts'] = True
        id_token_data['created_by'] = 'test'
        id_token_1 = OidcIdToken(data=id_token_data, raise_on_unknown=False)
        id_token_2 = OidcIdToken(iss=id_token_data['iss'], sub=id_token_data['sub'], aud=id_token_data['aud'],
                                 exp=id_token_data['exp'], iat=id_token_data['iat'], nonce=id_token_data['nonce'],
                                 auth_time=id_token_data['auth_time'], application='test')

        self.assertIsInstance(id_token_1, OidcIdToken)
        self.assertIsInstance(id_token_1.to_dict(), dict)
        self.assertEqual(id_token_1.key, id_token_2.key)

        dict_1 = id_token_1.to_dict()
        dict_2 = id_token_2.to_dict()
        del dict_1['created_ts']
        del dict_2['created_ts']

        self.assertEqual(dict_1, dict_2)

        with self.assertRaises(eduid_userdb.exceptions.UserHasUnknownData):
            OidcIdToken(data=id_token_data)

        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            OidcIdToken()

    def test_oidc_authz(self):
        id_token_data = token_response['id_token']
        id_token_data['created_ts'] = True
        id_token_data['created_by'] = 'test'
        id_token = OidcIdToken(data=token_response['id_token'], raise_on_unknown=False)

        token_response['created_ts'] = True
        token_response['created_by'] = 'test'
        oidc_authz_1 = OidcAuthorization(data=token_response, raise_on_unknown=False)
        oidc_authz_2 = OidcAuthorization(access_token=token_response['access_token'],
                                         token_type=token_response['token_type'], id_token=id_token,
                                         expires_in=token_response['expires_in'],
                                         refresh_token=token_response['refresh_token'], application='test',
                                         created_ts=True)

        self.assertIsInstance(oidc_authz_1, OidcAuthorization)
        self.assertIsInstance(oidc_authz_1.to_dict(), dict)
        self.assertEqual(oidc_authz_1.key, oidc_authz_2.key)

        dict_1 = oidc_authz_1.to_dict()
        dict_2 = oidc_authz_2.to_dict()
        del dict_1['created_ts']
        del dict_1['id_token']['created_ts']
        del dict_2['created_ts']
        del dict_2['id_token']['created_ts']

        self.assertEqual(dict_1, dict_2)

        with self.assertRaises(eduid_userdb.exceptions.UserHasUnknownData):
            OidcAuthorization(data=token_response)

        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            OidcAuthorization()

    def test_orcid(self):
        token_response['id_token']['created_ts'] = True
        token_response['id_token']['created_by'] = 'test'
        token_response['created_ts'] = True
        token_response['created_by'] = 'test'
        oidc_authz = OidcAuthorization(data=token_response, raise_on_unknown=False)
        orcid_1 = Orcid(id='https://op.example.org/user_orcid', oidc_authz=oidc_authz, application='test',
                        verified=True)
        orcid_2 = Orcid(data=orcid_1.to_dict())

        self.assertIsInstance(orcid_1, Orcid)
        self.assertIsInstance(orcid_1.to_dict(), dict)
        self.assertEqual(orcid_1.key, orcid_2.key)
        self.assertEqual(orcid_1.id, orcid_2.id)
        self.assertEqual(orcid_1.id, orcid_2.key)
        self.assertEqual(orcid_1.oidc_authz.key, orcid_2.oidc_authz.key)
        self.assertEqual(orcid_1.oidc_authz.id_token.key, orcid_2.oidc_authz.id_token.key)

        dict_1 = orcid_1.to_dict()
        dict_2 = orcid_2.to_dict()
        del dict_1['created_ts']
        del dict_1['oidc_authz']['created_ts']
        del dict_1['oidc_authz']['id_token']['created_ts']
        del dict_2['created_ts']
        del dict_2['oidc_authz']['created_ts']
        del dict_2['oidc_authz']['id_token']['created_ts']

        self.assertEqual(dict_1, dict_2)

        with self.assertRaises(eduid_userdb.exceptions.UserHasUnknownData):
            data = orcid_1.to_dict()
            data['unknown_key'] = 'test'
            Orcid(data=data)

        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            Orcid()
