import logging
import os
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import PurePath
from typing import Any
from uuid import uuid4

import pytest
from httpx import Response
from jwcrypto import jwt
from pydantic import ValidationError

from eduid.common.config.base import DataOwnerConfig, DataOwnerName, ScopeName
from eduid.common.config.parsers import load_config
from eduid.common.models.bearer_token import AuthnBearerToken, AuthSource, RequestedAccess, RequestedAccessDenied
from eduid.common.models.scim_base import SCIMSchema
from eduid.common.testing_base import normalised_data
from eduid.scimapi.config import ScimApiConfig
from eduid.scimapi.testing import BaseDBTestCase
from eduid.scimapi.tests.test_scimuser import ScimApiTestUserResourceBase
from eduid.userdb.scimapi import ScimApiProfile
from eduid.userdb.scimapi.userdb import ScimApiUser

logger = logging.getLogger(__name__)


class TestAuthnBearerToken(BaseDBTestCase):
    def setUp(self) -> None:
        if "EDUID_CONFIG_YAML" not in os.environ:
            os.environ["EDUID_CONFIG_YAML"] = "YAML_CONFIG_NOT_USED"

        self.datadir = PurePath(__file__).with_name("data")

        self.test_config = self._get_config()
        self.config = load_config(typ=ScimApiConfig, app_name="scimapi", ns="api", test_config=self.test_config)

    def _get_config(self) -> dict[str, Any]:
        config = super()._get_config()
        config["keystore_path"] = f"{self.datadir}/testing_jwks.json"
        config["signing_key_id"] = "testing-scimapi-2106210000"
        config["authorization_mandatory"] = False
        return config

    def test_scopes_canonicalization(self) -> None:
        """Test input data normalisation of the 'scopes' field."""
        config: ScimApiConfig = self.config.copy()
        domain = "eduid.se"
        config.scope_mapping[ScopeName("example.com")] = DataOwnerName(domain)
        config.scope_mapping[ScopeName("example.org")] = DataOwnerName(domain)
        # test no canonization
        token = AuthnBearerToken(
            config=self.config, version=1, scopes={ScopeName(domain)}, auth_source=AuthSource.CONFIG
        )
        assert token.scopes == {domain}
        # test no canonization, but normalisation
        token = AuthnBearerToken(
            config=self.config, version=1, scopes={ScopeName(domain.upper())}, auth_source=AuthSource.CONFIG
        )
        assert token.scopes == {domain}
        # test canonization
        token = AuthnBearerToken(
            config=self.config, version=1, scopes={ScopeName("example.org")}, auth_source=AuthSource.CONFIG
        )
        assert token.scopes == {domain}
        # test canonization and normalisation
        token = AuthnBearerToken(
            config=self.config, version=1, scopes={ScopeName("Example.Org")}, auth_source=AuthSource.CONFIG
        )
        assert token.scopes == {domain}
        # test canonization and normalisation, and de-duplication
        token = AuthnBearerToken(
            config=self.config,
            version=1,
            scopes={ScopeName("Example.Org"), ScopeName("example.coM"), ScopeName("other.foo")},
            auth_source=AuthSource.CONFIG,
        )
        assert token.scopes == {domain, "other.foo"}

    def test_invalid_scope(self) -> None:
        # test too short domain name
        with pytest.raises(ValidationError) as exc_info:
            AuthnBearerToken(config=self.config, version=1, scopes={ScopeName(".se")}, auth_source=AuthSource.CONFIG)
        assert normalised_data(exc_info.value.errors(), exclude_keys=["url"]) == normalised_data(
            [
                {
                    "ctx": {"min_length": 4},
                    "input": ".se",
                    "loc": ("scopes", 0),
                    "msg": "String should have at least 4 characters",
                    "type": "string_too_short",
                }
            ]
        ), f"Wrong error message: {exc_info.value.errors()}"

    def test_invalid_version(self) -> None:
        # test too short domain name
        with pytest.raises(ValidationError) as exc_info:
            AuthnBearerToken(
                config=self.config, version=99, scopes={ScopeName("eduid.se")}, auth_source=AuthSource.CONFIG
            )
        assert normalised_data(exc_info.value.errors(), exclude_keys=["url"]) == normalised_data(
            [
                {
                    "ctx": {"error": ValueError("Unknown version")},
                    "input": 99,
                    "loc": ("version",),
                    "msg": "Value error, Unknown version",
                    "type": "value_error",
                }
            ]
        ), f"Wrong error message: {exc_info.value.errors()}"

    def test_requested_access_canonicalization(self) -> None:
        """Test input data normalisation of the 'requested_access' field."""
        config: ScimApiConfig = self.config.copy()
        domain = ScopeName("eduid.se")
        config.scope_mapping[ScopeName("example.org")] = DataOwnerName(domain)
        config.scope_mapping[ScopeName("example.com")] = DataOwnerName(domain)
        _requested_access_type = self.config.requested_access_type
        assert _requested_access_type is not None
        # test no canonization
        token = AuthnBearerToken(
            config=self.config,
            version=1,
            scopes={ScopeName(domain)},
            requested_access=[RequestedAccess(type=_requested_access_type, scope=domain)],
            auth_source=AuthSource.CONFIG,
        )
        assert token.scopes == {domain}
        assert token.requested_access == [RequestedAccess(type=_requested_access_type, scope=domain)]
        # test no canonization, but normalisation
        token = AuthnBearerToken(
            config=self.config,
            version=1,
            scopes={ScopeName(domain.capitalize())},
            requested_access=[RequestedAccess(type=_requested_access_type, scope=ScopeName(domain.upper()))],
            auth_source=AuthSource.CONFIG,
        )
        assert token.scopes == {domain}
        assert token.requested_access == [RequestedAccess(type=_requested_access_type, scope=domain)]
        # test canonization
        token = AuthnBearerToken(
            config=self.config,
            version=1,
            scopes={domain},
            requested_access=[RequestedAccess(type=_requested_access_type, scope=ScopeName("example.org"))],
            auth_source=AuthSource.CONFIG,
        )
        assert token.scopes == {domain}
        assert token.requested_access == [RequestedAccess(type=_requested_access_type, scope=domain)]

    def test_invalid_requested_access_scope(self):
        # test too short domain name
        with pytest.raises(ValueError) as exc_info:
            AuthnBearerToken(
                config=self.config,
                version=1,
                scopes={"eduid.se"},
                requested_access=[RequestedAccess(type=self.config.requested_access_type, scope=".se")],
                auth_source=AuthSource.CONFIG,
            )
        assert normalised_data(exc_info.value.errors(), exclude_keys=["url"]) == normalised_data(
            [
                {
                    "ctx": {"min_length": 4},
                    "input": ".se",
                    "loc": ("scope",),
                    "msg": "String should have at least 4 characters",
                    "type": "string_too_short",
                }
            ]
        ), f"Wrong error message: {exc_info.value.errors()}"

    def test_requested_access_not_for_us(self):
        """Test with a 'requested_access' field with the wrong 'type' value."""
        domain = "eduid.se"
        # test no canonization
        with pytest.raises(ValueError) as exc_info:
            AuthnBearerToken(
                config=self.config,
                version=1,
                scopes={domain},
                requested_access=[RequestedAccess(type="someone else", scope=domain)],
                auth_source=AuthSource.CONFIG,
            )
        assert normalised_data(exc_info.value.errors(), exclude_keys=["url"]) == normalised_data(
            [
                {
                    "type": "value_error",
                    "loc": ("requested_access",),
                    "msg": "Value error, No requested access",
                    "input": [RequestedAccess(type="someone else", scope="eduid.se")],
                    "ctx": {"error": ValueError("No requested access")},
                }
            ]
        ), f"Wrong error message: {exc_info.value.errors()}"

    def test_regular_token(self):
        """Test the normal case. Login with access granted based on the single scope in the request."""
        domain = "eduid.se"
        claims = {
            "version": 1,
            "scopes": [domain],
            "auth_source": "config",
            "requested_access": [{"type": "scim-api", "scope": "eduid.se"}],
        }
        token = AuthnBearerToken(config=self.config, **claims)
        assert token.version == 1
        assert token.scopes == {domain}
        assert token.get_data_owner() == domain
        assert token.auth_source == AuthSource.CONFIG
        assert token.requested_access == [RequestedAccess(type="scim-api", scope=ScopeName("eduid.se"))]

    def test_multiple_access_requests_including_us(self):
        """Test when requested access has multiple requests. Only keep the request for the current resource."""
        domain = "eduid.se"
        token = AuthnBearerToken(
            config=self.config,
            version=1,
            scopes={domain},
            requested_access=[
                RequestedAccess(type="scim-api", scope=ScopeName(domain)),
                RequestedAccess(type="someone else", scope=ScopeName(domain)),
            ],
            auth_source=AuthSource.CONFIG,
        )
        assert token.version == 1
        assert token.scopes == {domain}
        assert token.get_data_owner() == domain
        assert token.auth_source == AuthSource.CONFIG
        # The token should only contain requested access to the current resource
        assert len(token.requested_access) == 1
        assert token.requested_access == [
            RequestedAccess(type="scim-api", scope=ScopeName(domain)),
        ]

    def test_interaction_token(self):
        """Test the normal case. Login with access granted based on the single scope in the request."""
        domain = "eduid.se"
        claims = {
            "version": 1,
            "saml_eppn": f"eppn@{domain}",
            "auth_source": "interaction",
            "requested_access": [{"type": "scim-api", "scope": "eduid.se"}],
        }
        token = AuthnBearerToken(config=self.config, **claims)
        assert token.version == 1
        assert token.scopes == {domain}
        assert token.get_data_owner() == domain
        assert token.auth_source == AuthSource.INTERACTION
        assert token.requested_access == [RequestedAccess(type="scim-api", scope=ScopeName("eduid.se"))]

    def test_regular_token_with_canonisation(self):
        """Test the normal case. Login with access granted based on the single scope in the request."""
        domain = "eduid.se"
        domain_alias = "eduid.example.edu"
        config = self.config.copy()
        config.scope_mapping[domain_alias] = domain
        claims = {"version": 1, "scopes": [domain_alias], "auth_source": "config"}
        token = AuthnBearerToken(config=self.config, **claims)
        assert token.get_data_owner() == domain

    def test_interaction_token_with_canonisation(self):
        """Test the normal case. Login with access granted based on the single scope in the request."""
        domain = DataOwnerName("eduid.se")
        domain_alias = ScopeName("eduid.example.edu")
        config = self.config.copy()
        config.scope_mapping[domain_alias] = domain
        claims = {"version": 1, "auth_source": "interaction", "saml_eppn": f"user@{domain_alias}"}
        token = AuthnBearerToken(config=self.config, **claims)
        assert token.get_data_owner() == domain

    def test_regular_token_upper_case(self):
        """
        Test the normal case. Login with access granted based on the single scope in the request.
        Scope provided in upper-case in the request.
        """
        domain = "eduid.se"
        claims = {"version": 1, "scopes": [domain.upper()], "auth_source": "config"}
        token = AuthnBearerToken(config=self.config, **claims)
        assert token.version == 1
        assert token.scopes == {domain}
        assert token.get_data_owner() == domain

    def test_unknown_scope(self):
        """Test login with a scope that has no data owner in the configuration."""
        domain = "example.org"
        claims = {"version": 1, "scopes": [domain], "auth_source": "config"}
        token = AuthnBearerToken(config=self.config, **claims)
        assert token.get_data_owner() is None

    def test_interaction_token_unknown_scope(self):
        """Test login with a scope that has no data owner in the configuration."""
        domain = "example.org"
        claims = {"version": 1, "saml_eppn": f"eppn{domain}", "auth_source": "interaction"}
        token = AuthnBearerToken(config=self.config, **claims)
        assert token.get_data_owner() is None

    def test_regular_token_multiple_scopes(self):
        """Test the normal case. Login with access granted based on the scope in the request that has a data owner
        in configuration (one extra scope provided in the request, named 'aaa' so it is checked first - and skipped).
        """
        domain = "eduid.se"
        claims = {"version": 1, "scopes": ["aaa.example.com", domain], "auth_source": "config"}
        token = AuthnBearerToken(config=self.config, **claims)
        assert token.get_data_owner() == domain

    def test_sudo_allowed(self) -> None:
        """Test the normal case when sudo:ing."""
        domain = ScopeName("eduid.se")
        sudoer = ScopeName("sudoer.example.org")
        config: ScimApiConfig = self.config.copy()
        config.scope_sudo = {sudoer: {domain}}
        config.requested_access_type = "api-test"
        claims = {
            "version": 1,
            "scopes": [sudoer],
            "requested_access": [{"type": config.requested_access_type, "scope": domain}],
            "auth_source": "config",
        }
        token = AuthnBearerToken(config=config, **claims)
        assert token.get_data_owner() == domain

    def test_sudo_not_allowed(self) -> None:
        """Test attempting to sudo, but the target scope (other-domain.example.org) is not in the list of
        allowed scopes for the requester."""
        domain = ScopeName("eduid.se")
        sudoer = ScopeName("sudoer.example.org")
        config: ScimApiConfig = self.config.copy()
        config.scope_sudo = {sudoer: {ScopeName("other-domain.example.org")}}
        config.requested_access_type = "api-test"
        claims = {
            "version": 1,
            "scopes": [sudoer],
            "requested_access": [{"type": config.requested_access_type, "scope": domain}],
            "auth_source": "config",
        }
        token = AuthnBearerToken(config=config, **claims)

        with pytest.raises(RequestedAccessDenied) as exc_info:
            assert token.get_data_owner() is None
        assert str(exc_info.value) == (
            "Requested access to scope eduid.se not in allow-list: other-domain.example.org, sudoer.example.org"
        )

    def test_sudo_unknown_scope(self) -> None:
        """Test attempting to sudo, but the target scope (other-domain.example.org)
        has no data owner in the configuration."""
        domain = ScopeName("other-domain.example.org")
        sudoer = ScopeName("sudoer.example.org")
        config: ScimApiConfig = self.config.copy()
        config.scope_sudo = {sudoer: {ScopeName("other-domain.example.org")}}
        config.requested_access_type = "api-test"
        claims = {
            "version": 1,
            "scopes": [sudoer],
            "requested_access": [{"type": config.requested_access_type, "scope": domain}],
            "auth_source": "config",
        }
        token = AuthnBearerToken(config=config, **claims)

        with pytest.raises(RequestedAccessDenied) as exc_info:
            assert token.get_data_owner() is None
        assert str(exc_info.value) == "Requested access to scope other-domain.example.org but no data owner found"

    def test_sudo_takes_precedence(self) -> None:
        """
        Test attempting to sudo from someone whose scope is a data owner,
        to another data owner they are allowed to sudo to.
        """
        domain = ScopeName("eduid.se")
        sudoer = ScopeName("sudoer.example.org")
        config: ScimApiConfig = self.config.copy()
        config.data_owners[DataOwnerName(sudoer)] = DataOwnerConfig(db_name="sudoer_db")
        config.scope_sudo = {sudoer: {domain}}
        config.requested_access_type = "api-test"
        claims = {
            "version": 1,
            "scopes": [sudoer],
            "requested_access": [{"type": config.requested_access_type, "scope": domain}],
            "auth_source": "config",
        }
        token = AuthnBearerToken(config=config, **claims)
        assert token.get_data_owner() == domain

    def test_sudo_with_canonicalisation(self) -> None:
        """
        Test attempting to sudo from someone whose scope is a data owner,
        to another data owner they are allowed to sudo to - using the scope canonisation in config.
        """
        domain = DataOwnerName("eduid.se")
        domain_alias = ScopeName("eduid.example.edu")
        sudoer = DataOwnerName("sudoer.example.org")
        config: ScimApiConfig = self.config.copy()
        config.data_owners[sudoer] = DataOwnerConfig(db_name="sudoer_db")
        config.scope_sudo = {ScopeName(sudoer): {ScopeName("eduid.se")}}
        config.scope_mapping[domain_alias] = domain
        config.requested_access_type = "api-test"
        claims = {
            "version": 1,
            "scopes": [sudoer],
            "requested_access": [{"type": config.requested_access_type, "scope": domain_alias}],
            "auth_source": "config",
        }
        token = AuthnBearerToken(config=config, **claims)
        assert token.get_data_owner() == domain


class TestAuthnUserResource(ScimApiTestUserResourceBase):
    def setUp(self) -> None:
        super().setUp()
        self.test_profile = ScimApiProfile(attributes={"displayName": "Test User 1"}, data={"test_key": "test_value"})

    def _get_config(self) -> dict:
        config = super()._get_config()
        config["keystore_path"] = f"{self.datadir}/testing_jwks.json"
        config["signing_key_id"] = "testing-scimapi-2106210000"
        config["authorization_mandatory"] = True
        return config

    def _get_user_from_api(self, user: ScimApiUser, bearer_token: str | None = None) -> Response:
        headers = self.headers
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"

        return self.client.get(url=f"/Users/{user.scim_id}", headers=headers)

    def _make_bearer_token(self, claims: Mapping[str, Any]) -> str:
        token = jwt.JWT(header={"alg": "ES256"}, claims=claims)
        jwk = list(self.context.jwks)[0]
        token.make_signed_token(jwk)
        return token.serialize()

    def test_get_user_no_authn(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id="test-id-1", profiles={"test": self.test_profile})
        response = self._get_user_from_api(db_user)
        self._assertScimError(response.json(), status=401, detail="No authentication header found")

    def test_get_user_bogus_token(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id="test-id-1", profiles={"test": self.test_profile})
        response = self._get_user_from_api(db_user, bearer_token="not a jws token")
        self._assertScimError(response.json(), status=401, detail="Bearer token error")

    def test_get_user_untrusted_token(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id="test-id-1", profiles={"test": self.test_profile})

        response = self._get_user_from_api(
            user=db_user,
            bearer_token=(
                "eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJudXRpZCB0ZXN0IiwiZXhwIjoxNjMxMzUyMzcxLCJpYXQiOjE2MzA0ODgzNzE"
                "sImlzcyI6Imh0dHBzOi8vbnV0aWQtYXV0aC10ZXN0LnN1bmV0LnNlIiwibmJmIjoxNjMwNDg4MzcxLCJzY29wZXMiOls"
                "iZGV2LmVkdWlkLnNlIl0sInN1YiI6ImZ0X3Rlc3RfMSIsInZlcnNpb24iOjF9.7bAIWqmlcvwj7n_ZLt3TBVBxPfkxz0"
                "VnyDlhPV86GL2HOBMR71Nhch0JGuXVZbs7NI2_93RQ5GsYye1J2d78CQ"
            ),
        )

        self._assertScimError(response.json(), status=401, detail="Bearer token error")

    def test_get_user_correct_token(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id="test-id-1", profiles={"test": self.test_profile})

        claims = {"scopes": ["eduid.se"], "version": 1, "auth_source": "config"}
        token = self._make_bearer_token(claims=claims)

        response = self._get_user_from_api(user=db_user, bearer_token=token)

        self._assertResponse(response, 200)

        _req = {
            SCIMSchema.NUTID_USER_V1.value: {"profiles": {"test": asdict(self.test_profile)}, "linked_accounts": []},
        }
        self._assertUserUpdateSuccess(_req, response, db_user)

    def test_get_user_interaction_token(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id="test-id-1", profiles={"test": self.test_profile})
        db_group = self.add_group_with_member(
            group_identifier=str(uuid4()),
            display_name=self.context.config.account_manager_default_group,
            user_identifier=str(db_user.scim_id),
        )

        claims = {
            "saml_eppn": "eppn@eduid.se",
            "version": 1,
            "auth_source": "interaction",
            "saml_assurance": [
                "http://www.swamid.se/policy/assurance/al1",
                "http://www.swamid.se/policy/assurance/al2",
                "http://www.swamid.se/policy/assurance/al3",
            ],
            "saml_entitlement": [
                "urn:mace:some:other:entitlement",
                f"{self.groupdb.graphdb.scope}:group:{db_group.graph.identifier}#eduid-iam",
            ],
        }
        token = self._make_bearer_token(claims=claims)

        response = self._get_user_from_api(user=db_user, bearer_token=token)

        self._assertResponse(response, 200)

        _req = {
            SCIMSchema.NUTID_USER_V1.value: {"profiles": {"test": asdict(self.test_profile)}, "linked_accounts": []},
        }
        self._assertUserUpdateSuccess(_req, response, db_user)

    def test_get_user_data_owner_not_configured(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id="test-id-1", profiles={"test": self.test_profile})
        claims = {"scopes": ["not_configured.se"], "version": 1, "auth_source": "config"}
        token = self._make_bearer_token(claims=claims)

        response = self._get_user_from_api(user=db_user, bearer_token=token)
        self._assertScimError(json=response.json(), status=401, detail="Unknown data_owner")
