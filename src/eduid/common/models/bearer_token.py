import logging
from collections.abc import Mapping
from copy import copy
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, StrictInt, field_validator, model_validator
from pydantic_core.core_schema import ValidationInfo

from eduid.common.config.base import AuthnBearerTokenConfig, DataOwnerName, ScopeName
from eduid.userdb.scimapi.groupdb import ScimApiGroupDB


class AuthSource(StrEnum):
    INTERACTION = "interaction"
    CONFIG = "config"
    MDQ = "mdq"
    TLSFED = "tlsfed"


class RequestedAccess(BaseModel):
    type: str
    scope: ScopeName | None = None


class AuthenticationError(Exception):
    pass


class AuthorizationError(Exception):
    pass


class RequestedAccessDenied(Exception):
    """Break out of get_data_owner when requested access (in the token) is not allowed"""

    pass


logger = logging.getLogger(__name__)


class AuthnBearerToken(BaseModel):
    config: AuthnBearerTokenConfig
    version: StrictInt
    auth_source: AuthSource
    requested_access: list[RequestedAccess] = Field(default=[])
    scopes: set[ScopeName] = Field(default=set())
    # saml interaction claims
    saml_issuer: str | None = None
    saml_assurance: list[str] | None = None
    saml_entitlement: list[str] | None = None
    saml_eppn: str | None = None
    saml_unique_id: str | None = None

    def __str__(self) -> str:
        return f"<{self.__class__.__name__}: scopes={self.scopes}, requested_access={self.requested_access}>"

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: int) -> int:
        if v != 1:
            raise ValueError("Unknown version")
        return v

    @model_validator(mode="before")
    @classmethod
    def set_scopes_from_saml_data(cls, values: dict[str, Any]) -> dict[str, Any]:
        # Get scope from saml identifier if the auth source is interaction and set it as scopes
        if values.get("auth_source") == AuthSource.INTERACTION.value:
            values["scopes"] = cls._get_scope_from_saml_data(values=values)
        return values

    @field_validator("scopes")
    def validate_scopes(cls, v: set[ScopeName], values: ValidationInfo) -> set[ScopeName]:
        config = values.data.get("config")
        if not config:
            raise ValueError("Can't validate without config")
        canonical_scopes = {config.scope_mapping.get(x, x) for x in v}
        return canonical_scopes

    @field_validator("requested_access")
    def validate_requested_access(cls, v: list[RequestedAccess], values: ValidationInfo) -> list[RequestedAccess]:
        config = values.data.get("config")
        if not config:
            raise ValueError("Can't validate without config")
        new_access: list[RequestedAccess] = []
        for this in v:
            if this.type != config.requested_access_type:
                # not meant for us
                continue
            if this.scope is not None:
                this.scope = config.scope_mapping.get(this.scope, this.scope)
            new_access += [this]
        if not new_access:
            logger.debug(f"Requested access: {v}")
            logger.debug(f"New access: {new_access}")
            raise ValueError("No requested access")
        return new_access

    @staticmethod
    def _get_scope_from_saml_data(values: Mapping[str, Any]) -> list[ScopeName]:
        saml_identifier = values.get("saml_eppn") or values.get("saml_unique_id")
        if not saml_identifier:
            return []
        try:
            scope = ScopeName(saml_identifier.split("@")[1])
        except IndexError:
            return []
        logger.info(f"Scope from saml data: {scope}")
        return [scope]

    def validate_auth_source(self) -> None:
        """
        Check if the auth source is any of the one we know of. If the auth source is config, mdq or tlsfed we
        can just let it through. If the auth source is interaction we need to check the saml data to make sure
        the user is allowed access to the data owner.
        """
        if self.auth_source in [AuthSource.CONFIG, AuthSource.MDQ, AuthSource.TLSFED]:
            logger.info(f"{self.auth_source} is a trusted auth source")
            return

        if self.auth_source == AuthSource.INTERACTION:
            assurances = self.saml_assurance or []
            # validate that the authentication meets the required assurance level
            for assurance_level in self.config.required_saml_assurance_level:
                if assurance_level in assurances:
                    logger.info(f"Allowed assurance level {assurance_level} is in saml data: {assurances}")
                    return
            raise AuthenticationError(
                f"Asserted SAML assurance level(s) ({assurances}) not in"
                f"allow-list: {self.config.required_saml_assurance_level}"
            )

        raise AuthenticationError(f"Unsupported authentication source: {self.auth_source}")

    def validate_saml_entitlements(self, data_owner: DataOwnerName, groupdb: ScimApiGroupDB | None = None) -> None:
        if groupdb is None:
            raise AuthenticationError("No groupdb provided, cannot validate saml entitlements.")

        default_name = self.config.account_manager_default_group
        account_manager_group_name = self.config.account_manager_group_mapping.get(data_owner, default_name)
        logger.debug(f"Checking for account manager group called {account_manager_group_name}")

        account_manager_group = groupdb.get_group_by_display_name(display_name=account_manager_group_name)
        if account_manager_group is None:
            raise AuthenticationError('No "Account Managers" group found for data owner')
        logger.debug(f"Found group {account_manager_group_name} with id {account_manager_group.graph.identifier}")

        # TODO: create a helper function to do this for all places where we do this dance in the repo
        # create the expected saml group id
        saml_group_id = f"{groupdb.graphdb.scope}:group:{account_manager_group.graph.identifier}#eduid-iam"
        # match against users entitlements
        entitlements = self.saml_entitlement or []
        if saml_group_id in entitlements:
            logger.debug(f"{saml_group_id} in {entitlements}")
            return
        logger.error(f"{saml_group_id} NOT in {entitlements}")
        raise AuthorizationError(f"Not authorized: {saml_group_id} not in saml entitlements")

    def get_data_owner(self) -> DataOwnerName | None:
        """
        Get the data owner to use.

        Primarily, this is done by searching for a data owner matching one of the 'scopes' in the
        JWT (scopes are inserted into the JWT by the Sunet auth server).

        Some requesters might be allowed (in configuration) to 'sudo' to certain data owners too,
        by passing 'access' to the Sunet authn server, which will be found as 'requested_access' in the JWT.

        A requester with more than one scope and more than one data owner can use the same mechanism
        as used to 'sudo' in order to indicate which of their data owners they want to use now.

        Example straight forward minimal JWT:

          {'version': 1, 'scopes': 'example.org'}

        Example 'sudo':

          {'version': 1, 'scopes': 'sudoer.example.org',
           requested_access: [{'type': 'scim-api', 'scope': 'example.edu'}]}
        """

        allowed_scopes = self._get_allowed_scopes(self.config)
        logger.debug(f"Request {self}, allowed scopes: {allowed_scopes}")

        # only support one requested access at a time for now and do not fall back to simple scope check if
        # requested access is used with a scope
        for this in self.requested_access:
            if this.scope is None:
                # scope is Optional
                continue
            _allowed = this.scope in allowed_scopes
            _found = self.config.data_owners.get(DataOwnerName(this.scope))
            logger.debug(f"Requested access to scope {this.scope}, allowed {_allowed}, found: {_found}")
            if not _allowed:
                _sorted = ", ".join(sorted(list(allowed_scopes)))
                raise RequestedAccessDenied(f"Requested access to scope {this.scope} not in allow-list: {_sorted}")
            if not _found:
                raise RequestedAccessDenied(f"Requested access to scope {this.scope} but no data owner found")
            if _allowed and _found:
                return DataOwnerName(this.scope)

        # sort to be deterministic
        for scope in sorted(list(self.scopes)):
            # checking allowed_scopes here might seem superfluous, but some client with multiple
            # scopes can request a specific one using the requested_access, and then only that one
            # scope is in allowed_scopes
            # TODO: the above comment is not true but it would be nice if it was
            #   allowed_scopes comes from config and will never be the requested_access scope
            _allowed = scope in allowed_scopes
            _found = self.config.data_owners.get(DataOwnerName(scope))
            logger.debug(f"Trying scope {scope}, allowed {_allowed}, found: {_found}")
            if _allowed and _found:
                return DataOwnerName(scope)

        return None

    def _get_allowed_scopes(self, config: AuthnBearerTokenConfig) -> set[ScopeName]:
        """
        Make a set of all the allowed scopes for the requester.

        The allowed scopes are always the scopes the requester has (the scopes come from federation metadata,
        the Sunet authn server inserts them in the JWT), and possibly others as found in configuration.
        """
        _scopes = copy(self.scopes)
        for this in self.scopes:
            if this in config.scope_sudo:
                _sudo_scopes = config.scope_sudo[this]
                logger.debug(f"Request from scope {this}, allowing sudo to scopes {_sudo_scopes}")
                _scopes.update(_sudo_scopes)
        return _scopes
