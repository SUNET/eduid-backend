import logging
import pprint
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Set

import satosa.context
import satosa.internal
from saml2.mdstore import MetaData
from satosa.attribute_mapping import AttributeMapper
from satosa.micro_services.base import ResponseMicroService

from eduid.scimapi.db.userdb import ScimApiUser, ScimApiUserDB, ScimEduidUserDB
from eduid.userdb import UserDB

logger = logging.getLogger(__name__)


@dataclass
class Config(object):
    mongo_uri: str
    idp_to_data_owner: Mapping[str, str]
    mfa_stepup_issuer_to_entity_id: Mapping[str, str]
    scope_to_data_owner: Mapping[str, str] = field(default_factory=dict)


class ScimAttributes(ResponseMicroService):
    """
    Add attributes from the scim db to the responses.
    """

    def __init__(self, config: Mapping[str, Any], internal_attributes: Dict[str, Any], *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = Config(**config)
        # Setup databases
        self.eduid_userdb = ScimEduidUserDB(db_uri=self.config.mongo_uri)
        logger.info(f'Connected to eduid db: {self.eduid_userdb}')
        self._userdbs: Dict[str, ScimApiUserDB] = {}
        self.converter = AttributeMapper(internal_attributes)
        # Get the internal attribute name for the eduPersonPrincipalName that will be
        # used to find users in the SCIM database
        _int = self.converter.to_internal('saml', {'eduPersonPrincipalName': 'something'})
        self.ext_id_attr = list(_int.keys())[0]
        logger.debug(f'SCIM externalId internal attribute name: {self.ext_id_attr}')

    def get_userdb_for_data_owner(self, data_owner: str) -> ScimApiUserDB:
        if data_owner not in self._userdbs:
            _owner = data_owner.replace('.', '_')  # replace dots with underscores
            coll = f'{_owner}__users'
            # TODO: rename old collection and remove this
            if data_owner == 'eduid.se':
                coll = 'profiles'
            self._userdbs[data_owner] = ScimApiUserDB(
                db_uri=self.config.mongo_uri, collection=coll, setup_indexes=False
            )
        return self._userdbs[data_owner]

    def process(
        self,
        context: satosa.context.Context,
        data: satosa.internal.InternalData,
    ) -> satosa.internal.InternalData:
        logger.debug(f'Data as dict:\n{pprint.pformat(data.to_dict())}')

        scopes: Set[str] = set()
        try:
            scopes = self._get_scopes_for_idp(context, data.auth_info.issuer)
        except Exception:
            logger.exception(f'Failed retrieving scopes for entityId {data.auth_info.issuer}')
        logger.debug(f'Scopes in metadata for IdP {data.auth_info.issuer}: {scopes}')

        user = self._get_user(data, scopes)
        if user:
            # TODO: handle multiple profiles beyond just picking the first one
            profiles = user.profiles.keys()
            if profiles:
                _name = sorted(profiles)[0]
                logger.info(f'Applying attributes from SCIM user {user.scim_id}, profile {_name}')
                profile = user.profiles[_name]

                update = self.converter.to_internal('saml', profile.attributes)

                for _name, _new in update.items():
                    _old = data.attributes.get(_name)
                    if _old != _new:
                        logger.debug(f'Changing attribute {_name} from {repr(_old)} to {repr(_new)}')
                        data.attributes[_name] = _new
            # Look for a linked account suitable for use for MFA stepup (in the stepup plugin that runs after this one)
            _stepup_accounts = []
            for acc in user.linked_accounts:
                logger.debug(f'Linked account: {acc}')
                _entity_id = self.config.mfa_stepup_issuer_to_entity_id.get(acc.issuer)
                if _entity_id and acc.parameters.get('mfa_stepup') is True:
                    _stepup_accounts += [
                        {'entity_id': _entity_id, 'identifier': acc.value, 'attribute': 'eduPersonPrincipalName'}
                    ]
            data.mfa_stepup_accounts = _stepup_accounts
            logger.debug(f'MFA stepup accounts: {data.mfa_stepup_accounts}')

        return super().process(context, data)

    def _get_scopes_for_idp(self, context: satosa.context.Context, entity_id: str) -> Set[str]:
        res = set()
        logger.debug(f'Looking for metadata scope for entityId {entity_id}')
        for _md_name, _metadata in context.internal_data[context.KEY_METADATA_STORE].metadata.items():
            if not isinstance(_metadata, MetaData):
                logger.debug(f'Element {_metadata} was not MetaData')
                continue
            if entity_id not in _metadata:
                logger.debug(f'entityId {entity_id} not present in this metadata ({_md_name})')
                continue
            idpsso = _metadata[entity_id].get('idpsso_descriptor', {})

            res.update(_extract_saml_scope(idpsso))
        return res

    def _get_user(self, data: satosa.internal.InternalData, scopes: Set[str]) -> Optional[ScimApiUser]:
        # Look for explicit information about what data owner to use for this IdP
        data_owner: Optional[str] = self.config.idp_to_data_owner.get(data.auth_info.issuer)
        if data_owner:
            logger.debug(f'Data owner for issuer {data.auth_info.issuer}: {data_owner}')
        else:
            _sorted_scopes = sorted(list(scopes))
            # Look for a scope in the list 'scopes' that has explicit mapping information in config
            for _scope in _sorted_scopes:
                if _scope in self.config.scope_to_data_owner:
                    data_owner = self.config.scope_to_data_owner[_scope]
                    logger.debug(f'Data owner for scope {_scope}: {data_owner}')
                    break
            if not data_owner and _sorted_scopes:
                data_owner = _sorted_scopes[0]
                logger.debug(f'Using first scope as data owner: {_sorted_scopes}')
        if not data_owner:
            logger.warning(f'No data owner for issuer {data.auth_info.issuer}')
            return None

        logger.info(f'entityId {data.auth_info.issuer}, scope(s) {scopes}, data_owner {data_owner}')

        userdb = self.get_userdb_for_data_owner(data_owner)

        _ext_ids = data.attributes.get(self.ext_id_attr, [])
        if len(_ext_ids) != 1:
            logger.warning(f'Got more or less than one externalId using attribute {self.ext_id_attr}: {_ext_ids}')
            return None

        ext_id = _ext_ids[0]
        user = userdb.get_user_by_external_id(ext_id)
        if user:
            logger.info(f'Found SCIM user {user.scim_id} using {self.ext_id_attr} {ext_id} (data owner: {data_owner})')
        else:
            logger.info(f'No user found using {self.ext_id_attr} {ext_id}')
        return user


def _extract_saml_scope(idpsso: List[Mapping[str, Any]]) -> Set[str]:
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
        if top_level.get('__class__') != 'urn:oasis:names:tc:SAML:2.0:metadata&IDPSSODescriptor':
            continue
        if 'extensions' in top_level:
            if top_level['extensions'].get('__class__') == 'urn:oasis:names:tc:SAML:2.0:metadata&Extensions':
                for element in top_level['extensions'].get('extension_elements', []):
                    if element.get('__class__') != 'urn:mace:shibboleth:metadata:1.0&Scope':
                        continue
                    _text = element.get('text')
                    if isinstance(element['text'], str):
                        res.add(element['text'])
    return res
