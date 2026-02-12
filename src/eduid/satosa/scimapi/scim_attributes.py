import logging
import pprint
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import satosa.context
import satosa.internal
from satosa.attribute_mapping import AttributeMapper
from satosa.exception import SATOSAAuthenticationError
from satosa.micro_services.base import ResponseMicroService
from satosa.routing import STATE_KEY as ROUTER_STATE_KEY

from eduid.satosa.scimapi.common import MfaStepupAccount, get_metadata, store_mfa_stepup_accounts
from eduid.userdb.scimapi import ScimApiGroup, ScimApiGroupDB
from eduid.userdb.scimapi.userdb import ScimApiUser, ScimApiUserDB, ScimEduidUserDB

logger = logging.getLogger(__name__)


@dataclass
class Config:
    mongo_uri: str
    neo4j_uri: str | None = None
    neo4j_config: dict = field(default_factory=dict)
    only_configure_and_expose_scim: bool = False
    allow_users_not_in_database: Mapping[str, bool] = field(default_factory=lambda: {"default": False})
    fallback_data_owner: str | None = None
    idp_to_data_owner: Mapping[str, str] = field(default_factory=dict)
    mfa_stepup_issuer_to_entity_id: Mapping[str, str] = field(default_factory=dict)
    scope_to_data_owner: Mapping[str, str] = field(default_factory=dict)
    virt_idp_to_data_owner: Mapping[str, str] = field(default_factory=dict)


@dataclass
class UserGroups:
    data_owner: str
    member: list[ScimApiGroup] = field(default_factory=list)
    manager: list[ScimApiGroup] = field(default_factory=list)


class ScimAttributes(ResponseMicroService):
    """
    Add attributes from the scim db to the responses.
    """

    def __init__(
        self, config: Mapping[str, Any], internal_attributes: dict[str, Any], *args: Any, **kwargs: Any
    ) -> None:
        super().__init__(*args, **kwargs)

        self.config = Config(**config)
        # Setup databases
        self.eduid_userdb = ScimEduidUserDB(db_uri=self.config.mongo_uri)
        logger.info(f"Connected to eduid db: {self.eduid_userdb}")
        self._userdbs: dict[str, ScimApiUserDB] = {}
        self._groupdbs: dict[str, ScimApiGroupDB] = {}
        self.converter = AttributeMapper(internal_attributes)
        # Get the internal attribute name for the eduPersonPrincipalName that will be
        # used to find users in the SCIM database
        _int = self.converter.to_internal("saml", {"eduPersonPrincipalName": "something"})
        self.ext_id_attr = list(_int.keys())[0]
        logger.debug(f"SCIM externalId internal attribute name: {self.ext_id_attr}")

    def get_userdb_for_data_owner(self, data_owner: str) -> ScimApiUserDB:
        if data_owner not in self._userdbs:
            _owner = data_owner.replace(".", "_")  # replace dots with underscores
            coll = f"{_owner}__users"
            # TODO: rename old collection and remove this
            if data_owner == "eduid.se":
                coll = "profiles"
            self._userdbs[data_owner] = ScimApiUserDB(
                db_uri=self.config.mongo_uri, collection=coll, setup_indexes=False
            )
        return self._userdbs[data_owner]

    def get_groupdb_for_data_owner(self, data_owner: str) -> ScimApiGroupDB | None:
        if self.config.neo4j_uri is None:
            # be able to turn off group lookups by unsetting neo4j_uri
            logger.info("No neo4j_uri set in config, group lookups will be turned off.")
            return None
        if data_owner not in self._groupdbs:
            _owner = data_owner.replace(".", "_")  # replace dots with underscores
            self._groupdbs[data_owner] = ScimApiGroupDB(
                neo4j_uri=self.config.neo4j_uri,
                neo4j_config=self.config.neo4j_config,
                scope=data_owner,
                mongo_uri=self.config.mongo_uri,
                mongo_dbname="eduid_scimapi",
                mongo_collection=f"{_owner}__groups",
            )
        return self._groupdbs[data_owner]

    def process(
        self,
        context: satosa.context.Context,
        data: satosa.internal.InternalData,
    ) -> satosa.internal.InternalData:
        logger.debug(f"Data as dict:\n{pprint.pformat(data.to_dict())}")
        scopes: set[str] = set()

        try:
            scopes = self._get_scopes_for_idp(context, data.auth_info.issuer)
        except Exception:
            logger.exception(f"Failed retrieving scopes for entityId {data.auth_info.issuer}")
        logger.debug(f"Scopes in metadata for IdP {data.auth_info.issuer}: {scopes}")

        frontend_name = context.state.get(ROUTER_STATE_KEY)
        data_owner = self._get_data_owner(data, scopes, frontend_name)

        # Configure dataowner to "no-scim" for Virtual IdPs that provide their own data/attributes. E.g Microsoft Entra.
        if data_owner == "no-scim":
            return super().process(context, data)

        # This is the easiest way I can come up with without needing duplicated configuration
        # regarding the database for different micro_services or refactor the database connection/calls
        # to a shared class.
        # Make sure to delete from `data` before handing the request to satosa due to serialization problems.
        if self.config.only_configure_and_expose_scim:
            data.update({"scim_class_from_ScimAttributes": self})
            data.update({"data_owner": data_owner})

            return super().process(context, data)

        logger.info(f"entityId {data.auth_info.issuer}, scope(s) {scopes}, data_owner {data_owner}")
        user = self._get_user(data, data_owner)
        user_groups = self._get_user_groups(user, data_owner)

        if user:
            logger.debug(f"Found user: {user}")
            data = self._process_user(user=user, data=data)
        else:
            default_allow = self.config.allow_users_not_in_database.get("default", False)
            allow_users_not_in_database = self.config.allow_users_not_in_database.get(frontend_name, default_allow)

            if not allow_users_not_in_database:
                raise SATOSAAuthenticationError(context.state, "User not found in database")

        if user_groups:
            logger.debug(f"Found user groups: {user_groups}")
            data = self._process_groups(data_owner=data_owner, user_groups=user_groups, data=data)

        return super().process(context, data)

    def _process_user(self, user: ScimApiUser, data: satosa.internal.InternalData) -> satosa.internal.InternalData:
        # TODO: handle multiple profiles beyond just picking the first one
        profiles = user.profiles.keys()
        if profiles:
            _name = sorted(profiles)[0]
            logger.info(f"Applying attributes from SCIM user {user.scim_id}, profile {_name}")
            profile = user.profiles[_name]

            update = self.converter.to_internal("saml", profile.attributes)

            for _name, _new in update.items():
                _old = data.attributes.get(_name)
                if _old != _new:
                    logger.debug(f"Changing attribute {_name} from {_old!r} to {_new!r}")
                    data.attributes[_name] = _new

        # Look for a linked account suitable for use for MFA stepup (in the stepup plugin that runs after this one)
        _stepup_accounts: list[MfaStepupAccount] = []
        for acc in user.linked_accounts:
            logger.debug(f"Linked account: {acc}")
            _entity_id = self.config.mfa_stepup_issuer_to_entity_id.get(acc.issuer)
            if _entity_id and acc.parameters.get("mfa_stepup") is True:
                _stepup_accounts += [
                    MfaStepupAccount(
                        entity_id=_entity_id,
                        identifier=acc.value,
                    )
                ]
        store_mfa_stepup_accounts(data=data, accounts=_stepup_accounts)
        logger.debug(f"MFA stepup accounts: {data.mfa_stepup_accounts}")

        return data

    def _process_groups(
        self, data_owner: str | None, user_groups: UserGroups, data: satosa.internal.InternalData
    ) -> satosa.internal.InternalData:
        if data_owner is None:
            return data

        if data.attributes.get("edupersonentitlement") is None:
            data.attributes["edupersonentitlement"] = []

        for member_group in user_groups.member:
            data.attributes["edupersonentitlement"].append(
                f"{user_groups.data_owner}:group:{member_group.graph.identifier}#eduid-iam"
            )
        for manager_group in user_groups.manager:
            data.attributes["edupersonentitlement"].append(
                f"{user_groups.data_owner}:group:{manager_group.graph.identifier}:role=manager#eduid-iam"
            )

        logger.debug(f"edupersonentitlement after groups: {data.attributes['edupersonentitlement']}")
        return data

    def _get_scopes_for_idp(self, context: satosa.context.Context, entity_id: str) -> set[str]:
        res = set()
        logger.debug(f"Looking for metadata scope for entityId {entity_id}")
        for _metadata in get_metadata(context):
            if entity_id not in _metadata:
                logger.debug(f"entityId {entity_id} not present in this metadata")
                continue
            idpsso = _metadata[entity_id].get("idpsso_descriptor", {})

            res.update(_extract_saml_scope(idpsso))
        return res

    def _get_data_owner(self, data: satosa.internal.InternalData, scopes: set[str], frontend_name: str) -> str | None:
        # Look for explicit information about what data owner to use for this IdP
        issuer = frontend_name
        data_owner: str | None = self.config.virt_idp_to_data_owner.get(issuer)
        # Fallback to issuer. E.g Skolverkets idpproxy
        if not data_owner:
            issuer = data.auth_info.issuer
            data_owner = self.config.idp_to_data_owner.get(issuer)

        if data_owner:
            logger.debug(f"Data owner for issuer {issuer}: {data_owner}")
        else:
            fallback_data_owner = self.config.fallback_data_owner
            if fallback_data_owner is not None:
                data_owner = fallback_data_owner
                logger.debug(f"Using fallback data owner {data_owner} for {issuer}")
            else:
                _sorted_scopes = sorted(list(scopes))
                # Look for a scope in the list 'scopes' that has explicit mapping information in config
                for _scope in _sorted_scopes:
                    if _scope in self.config.scope_to_data_owner:
                        data_owner = self.config.scope_to_data_owner[_scope]
                        logger.debug(f"Data owner for scope {_scope}: {data_owner}")
                        break

        if not data_owner:
            logger.warning(f"No data owner for issuer {issuer}")
            return None

        return data_owner

    def _get_user(self, data: satosa.internal.InternalData, data_owner: str | None) -> ScimApiUser | None:
        if data_owner is None:
            return None

        userdb = self.get_userdb_for_data_owner(data_owner)

        _ext_ids = data.attributes.get(self.ext_id_attr, [])
        if len(_ext_ids) != 1:
            logger.warning(f"Got more or less than one externalId using attribute {self.ext_id_attr}: {_ext_ids}")
            return None

        ext_id = _ext_ids[0]
        user = userdb.get_user_by_external_id(ext_id)
        if user:
            logger.info(f"Found SCIM user {user.scim_id} using {self.ext_id_attr} {ext_id} (data owner: {data_owner})")
        else:
            logger.info(f"No user found using {self.ext_id_attr} {ext_id}")
        return user

    def _get_user_groups(self, user: ScimApiUser | None, data_owner: str | None) -> UserGroups | None:
        if user is None or data_owner is None:
            return None

        groupdb = self.get_groupdb_for_data_owner(data_owner)
        if groupdb is None:
            return None

        return UserGroups(
            data_owner=groupdb.graphdb.scope,
            member=groupdb.get_groups_for_user_identifer(user.scim_id),
            manager=groupdb.get_groups_owned_by_user_identifier(user.scim_id),
        )


def _extract_saml_scope(idpsso: list[Mapping[str, Any]]) -> set[str]:
    """
    Extract scopes from SAML extension data that looks something like this:

    [
    {
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&IDPSSODescriptor",
        "extensions": {
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions",
            "extension_elements": [
                {
                    "__class__": "urn:mace:shibboleth:metadata:1.0&Scope",
                    "text": "eduid.se",
                    "regexp": "false"
                },
                {
                    "__class__": "urn:oasis:names:tc:SAML:metadata:ui&UIInfo",
                    ...
                }
            ]
        }
    }]
    """
    res = set()
    for top_level in idpsso:
        if top_level.get("__class__") != "urn:oasis:names:tc:SAML:2.0:metadata&IDPSSODescriptor":
            continue
        if "extensions" in top_level:
            if top_level["extensions"].get("__class__") == "urn:oasis:names:tc:SAML:2.0:metadata&Extensions":
                for element in top_level["extensions"].get("extension_elements", []):
                    if element.get("__class__") != "urn:mace:shibboleth:metadata:1.0&Scope":
                        continue
                    _text = element.get("text")
                    if isinstance(element["text"], str):
                        res.add(element["text"])
    return res
