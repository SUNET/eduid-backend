from dataclasses import asdict
from typing import Any, Dict, Mapping, Optional
from uuid import uuid4

import pytest
from jwcrypto import jwt
from requests import Response

from eduid.scimapi.db.common import ScimApiProfile
from eduid.scimapi.db.userdb import ScimApiUser
from eduid.scimapi.models.scimbase import SCIMSchema
from eduid.scimapi.tests.test_scimuser import ScimApiTestUserResourceBase


class TestAuthnUserResource(ScimApiTestUserResourceBase):
    def setUp(self) -> None:
        super().setUp()
        self.test_profile = ScimApiProfile(attributes={'displayName': 'Test User 1'}, data={'test_key': 'test_value'})

    def _get_config(self) -> Dict:
        config = super()._get_config()
        config['keystore_path'] = f'{self.datadir}/testing_jwks.json'
        config['signing_key_id'] = 'testing-scimapi-2106210000'
        config['authorization_mandatory'] = True
        return config

    def _get_user_from_api(self, user: ScimApiUser, bearer_token: Optional[str] = None) -> Response:
        headers = self.headers
        if bearer_token:
            headers['Authorization'] = f'Bearer {bearer_token}'

        return self.client.get(url=f'/Users/{user.scim_id}', headers=headers)

    def _make_bearer_token(self, claims: Mapping[str, Any]) -> str:
        token = jwt.JWT(header={'alg': 'ES256'}, claims=claims)
        jwk = list(self.context.jwks)[0]
        token.make_signed_token(jwk)
        return token.serialize()

    def test_get_user_no_authn(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id='test-id-1', profiles={'test': self.test_profile})
        response = self._get_user_from_api(db_user)
        self._assertResponse(response, 401)
        assert response.text == 'No authentication header found'

    def test_get_user_bogus_token(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id='test-id-1', profiles={'test': self.test_profile})
        with pytest.raises(ValueError):
            response = self._get_user_from_api(db_user, bearer_token='not a jws token')
        # TODO: Return a proper error to the user?
        # self._assertResponse(response, 401)
        # assert response.text == 'Token format unrecognized'

    def test_get_user_untrusted_token(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id='test-id-1', profiles={'test': self.test_profile})

        response = self._get_user_from_api(
            user=db_user,
            bearer_token=(
                'eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJudXRpZCB0ZXN0IiwiZXhwIjoxNjMxMzUyMzcxLCJpYXQiOjE2MzA0ODgzNzE'
                'sImlzcyI6Imh0dHBzOi8vbnV0aWQtYXV0aC10ZXN0LnN1bmV0LnNlIiwibmJmIjoxNjMwNDg4MzcxLCJzY29wZXMiOls'
                'iZGV2LmVkdWlkLnNlIl0sInN1YiI6ImZ0X3Rlc3RfMSIsInZlcnNpb24iOjF9.7bAIWqmlcvwj7n_ZLt3TBVBxPfkxz0'
                'VnyDlhPV86GL2HOBMR71Nhch0JGuXVZbs7NI2_93RQ5GsYye1J2d78CQ'
            ),
        )

        self._assertResponse(response, 401)
        assert response.headers['content-type'] == 'text/plain; charset=utf-8'
        assert response.text == 'Bearer token error'

    def test_get_user_correct_token(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id='test-id-1', profiles={'test': self.test_profile})

        claims = {'data_owner': 'eduid.se'}
        token = self._make_bearer_token(claims=claims)

        response = self._get_user_from_api(user=db_user, bearer_token=token)

        self._assertResponse(response, 200)

        _req = {
            SCIMSchema.NUTID_USER_V1.value: {'profiles': {'test': asdict(self.test_profile)}, 'linked_accounts': []},
        }
        self._assertUserUpdateSuccess(_req, response, db_user)
