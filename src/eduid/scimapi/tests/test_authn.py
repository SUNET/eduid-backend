import os
from dataclasses import asdict
from pathlib import PurePath
from typing import Any, Dict, Mapping, Optional
from uuid import uuid4

import loguru
import pytest
from jwcrypto import jwt
from requests import Response

from eduid.common.config.parsers import load_config
from eduid.scimapi.config import DataOwner, ScimApiConfig
from eduid.scimapi.db.common import ScimApiProfile
from eduid.scimapi.db.userdb import ScimApiUser
from eduid.scimapi.middleware import AuthnBearerToken, SudoAccess
from eduid.scimapi.models.scimbase import SCIMSchema
from eduid.scimapi.testing import BaseDBTestCase
from eduid.scimapi.tests.test_scimuser import ScimApiTestUserResourceBase


class TestAuthnBearerToken(BaseDBTestCase):
    def setUp(self) -> None:
        if 'EDUID_CONFIG_YAML' not in os.environ:
            os.environ['EDUID_CONFIG_YAML'] = 'YAML_CONFIG_NOT_USED'

        self.datadir = PurePath(__file__).with_name('data')

        self.test_config = self._get_config()
        self.config = load_config(typ=ScimApiConfig, app_name='scimapi', ns='api', test_config=self.test_config)

    def _get_config(self) -> Dict:
        config = super()._get_config()
        config['keystore_path'] = f'{self.datadir}/testing_jwks.json'
        config['signing_key_id'] = 'testing-scimapi-2106210000'
        config['authorization_mandatory'] = False
        return config

    def test_scopes_canonicalization(self):
        """ Test input data normalisation of the 'scopes' field. """
        config: ScimApiConfig = self.config.copy()
        domain = 'eduid.se'
        config.scope_mapping['example.com'] = domain
        config.scope_mapping['example.org'] = domain
        # test no canonization
        token = AuthnBearerToken(scim_config=self.config, version=1, scopes={domain})
        assert token.scopes == {domain}
        # test no canonization, but normalisation
        token = AuthnBearerToken(scim_config=self.config, version=1, scopes={domain.upper()})
        assert token.scopes == {domain}
        # test canonization
        token = AuthnBearerToken(scim_config=self.config, version=1, scopes={'example.org'})
        assert token.scopes == {domain}
        # test canonization and normalisation
        token = AuthnBearerToken(scim_config=self.config, version=1, scopes={'Example.Org'})
        assert token.scopes == {domain}
        # test canonization and normalisation, and de-duplication
        token = AuthnBearerToken(scim_config=self.config, version=1, scopes={'Example.Org', 'example.coM', 'other.foo'})
        assert token.scopes == {domain, 'other.foo'}

    def test_invalid_scope(self):
        # test too short domain name
        with pytest.raises(ValueError) as exc_info:
            AuthnBearerToken(scim_config=self.config, version=1, scopes={'.se'})
        assert exc_info.value.errors() == [
            {
                'ctx': {'limit_value': 4},
                'loc': ('scopes', 0),
                'msg': 'ensure this value has at least 4 characters',
                'type': 'value_error.any_str.min_length',
            }
        ]

    def test_invalid_version(self):
        # test too short domain name
        with pytest.raises(ValueError) as exc_info:
            AuthnBearerToken(scim_config=self.config, version=99, scopes={'eduid.se'})
        assert exc_info.value.errors() == [{'loc': ('version',), 'msg': 'Unknown version', 'type': 'value_error'}]

    def test_requested_access_canonicalization(self):
        """ Test input data normalisation of the 'requested_access' field. """
        config: ScimApiConfig = self.config.copy()
        domain = 'eduid.se'
        config.scope_mapping['example.com'] = domain
        config.scope_mapping['example.org'] = domain
        # test no canonization
        token = AuthnBearerToken(
            scim_config=self.config,
            version=1,
            scopes={domain},
            requested_access=[SudoAccess(type=self.config.requested_access_type, scope=domain)],
        )
        assert token.scopes == {domain}
        assert token.requested_access == [SudoAccess(type=self.config.requested_access_type, scope=domain)]
        # test no canonization, but normalisation
        token = AuthnBearerToken(
            scim_config=self.config,
            version=1,
            scopes={domain.capitalize()},
            requested_access=[SudoAccess(type=self.config.requested_access_type, scope=domain.upper())],
        )
        assert token.scopes == {domain}
        assert token.requested_access == [SudoAccess(type=self.config.requested_access_type, scope=domain)]
        # test canonization
        token = AuthnBearerToken(
            scim_config=self.config,
            version=1,
            scopes={domain},
            requested_access=[SudoAccess(type=self.config.requested_access_type, scope='example.org')],
        )
        assert token.scopes == {domain}
        assert token.requested_access == [SudoAccess(type=self.config.requested_access_type, scope=domain)]

    def test_invalid_requested_access_scope(self):
        # test too short domain name
        with pytest.raises(ValueError) as exc_info:
            AuthnBearerToken(
                scim_config=self.config,
                version=1,
                scopes={'eduid.se'},
                requested_access=[SudoAccess(type=self.config.requested_access_type, scope='.se')],
            )
        assert exc_info.value.errors() == [
            {
                'ctx': {'limit_value': 4},
                'loc': ('scope',),
                'msg': 'ensure this value has at least 4 characters',
                'type': 'value_error.any_str.min_length',
            }
        ]

    def test_requested_access_not_for_us(self):
        """ Test with a 'requested_access' field with the wrong 'type' value. """
        domain = 'eduid.se'
        # test no canonization
        token = AuthnBearerToken(
            scim_config=self.config,
            version=1,
            scopes={domain},
            requested_access=[SudoAccess(type='someone else', scope=domain)],
        )
        assert token.scopes == {domain}
        assert token.requested_access == []

    def test_regular_token(self):
        """ Test the normal case. Login with access granted based on the single scope in the request. """
        domain = 'eduid.se'
        claims = {'version': 1, 'scopes': [domain]}
        token = AuthnBearerToken(scim_config=self.config, **claims)
        assert token.version == 1
        assert token.scopes == {domain}
        assert token.get_data_owner(logger=loguru.logger) == domain

    def test_regular_token_with_canonisation(self):
        """ Test the normal case. Login with access granted based on the single scope in the request. """
        domain = 'eduid.se'
        domain_alias = 'eduid.example.edu'
        config = self.config.copy()
        config.scope_mapping[domain_alias] = domain
        claims = {'version': 1, 'scopes': [domain_alias]}
        token = AuthnBearerToken(scim_config=self.config, **claims)
        assert token.get_data_owner(logger=loguru.logger) == domain

    def test_regular_token_upper_case(self):
        """
        Test the normal case. Login with access granted based on the single scope in the request.
        Scope provided in upper-case in the request.
        """
        domain = 'eduid.se'
        claims = {'version': 1, 'scopes': [domain.upper()]}
        token = AuthnBearerToken(scim_config=self.config, **claims)
        assert token.version == 1
        assert token.scopes == {domain}
        assert token.get_data_owner(logger=loguru.logger) == domain

    def test_unknown_scope(self):
        """ Test login with a scope that has no data owner in the configuration. """
        domain = 'example.org'
        claims = {'version': 1, 'scopes': [domain]}
        token = AuthnBearerToken(scim_config=self.config, **claims)
        assert token.get_data_owner(logger=loguru.logger) is None

    def test_regular_token_multiple_scopes(self):
        """ Test the normal case. Login with access granted based on the scope in the request that has a data owner
        in configuration (one extra scope provided in the request, named 'aaa' so it is checked first - and skipped).
         """
        domain = 'eduid.se'
        claims = {'version': 1, 'scopes': ['aaa.example.com', domain]}
        token = AuthnBearerToken(scim_config=self.config, **claims)
        assert token.get_data_owner(logger=loguru.logger) == domain

    def test_sudo_allowed(self):
        """ Test the normal case when sudo:ing. """
        domain = 'eduid.se'
        sudoer = 'sudoer.example.org'
        config: ScimApiConfig = self.config.copy()
        config.scope_sudo = {sudoer: {domain}}
        config.requested_access_type = 'api-test'
        claims = {
            'version': 1,
            'scopes': [sudoer],
            'requested_access': [{'type': config.requested_access_type, 'scope': domain}],
        }
        token = AuthnBearerToken(scim_config=config, **claims)
        assert token.get_data_owner(logger=loguru.logger) == domain

    def test_sudo_not_allowed(self):
        """ Test attempting to sudo, but the target scope (other-domain.example.org) is not in the list of
        allowed scopes for the requester. """
        domain = 'eduid.se'
        sudoer = 'sudoer.example.org'
        config: ScimApiConfig = self.config.copy()
        config.scope_sudo = {sudoer: {'other-domain.example.org'}}
        config.requested_access_type = 'api-test'
        claims = {
            'version': 1,
            'scopes': [sudoer],
            'requested_access': [{'type': config.requested_access_type, 'scope': domain}],
        }
        token = AuthnBearerToken(scim_config=config, **claims)
        assert token.get_data_owner(logger=loguru.logger) == None

    def test_sudo_takes_precedence(self):
        """
        Test attempting to sudo from someone whose scope is a data owner,
        to another data owner they are allowed to sudo to.
        """
        domain = 'eduid.se'
        sudoer = 'sudoer.example.org'
        config: ScimApiConfig = self.config.copy()
        config.data_owners[sudoer] = DataOwner(db_name='sudoer_db')
        config.scope_sudo = {sudoer: {'eduid.se'}}
        config.requested_access_type = 'api-test'
        claims = {
            'version': 1,
            'scopes': [sudoer],
            'requested_access': [{'type': config.requested_access_type, 'scope': domain}],
        }
        token = AuthnBearerToken(scim_config=config, **claims)
        assert token.get_data_owner(logger=loguru.logger) == domain

    def test_sudo_with_canonicalisation(self):
        """
        Test attempting to sudo from someone whose scope is a data owner,
        to another data owner they are allowed to sudo to - using the scope canonisation in config.
        """
        domain = 'eduid.se'
        domain_alias = 'eduid.example.edu'
        sudoer = 'sudoer.example.org'
        config: ScimApiConfig = self.config.copy()
        config.data_owners[sudoer] = DataOwner(db_name='sudoer_db')
        config.scope_sudo = {sudoer: {'eduid.se'}}
        config.scope_mapping[domain_alias] = domain
        config.requested_access_type = 'api-test'
        claims = {
            'version': 1,
            'scopes': [sudoer],
            'requested_access': [{'type': config.requested_access_type, 'scope': domain_alias}],
        }
        token = AuthnBearerToken(scim_config=config, **claims)
        assert token.get_data_owner(logger=loguru.logger) == domain


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
        response = self._get_user_from_api(db_user, bearer_token='not a jws token')
        self._assertResponse(response, 401)
        assert response.text == 'Bearer token error'

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

        claims = {'scopes': ['eduid.se'], 'version': 1}
        token = self._make_bearer_token(claims=claims)

        response = self._get_user_from_api(user=db_user, bearer_token=token)

        self._assertResponse(response, 200)

        _req = {
            SCIMSchema.NUTID_USER_V1.value: {'profiles': {'test': asdict(self.test_profile)}, 'linked_accounts': []},
        }
        self._assertUserUpdateSuccess(_req, response, db_user)
