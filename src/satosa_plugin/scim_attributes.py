import logging
import pprint
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

import satosa.context
import satosa.internal
from satosa.attribute_mapping import AttributeMapper
from satosa.micro_services.base import ResponseMicroService

from eduid_userdb import UserDB

from eduid_scimapi.user import ScimApiUser
from eduid_scimapi.userdb import ScimApiUserDB

logger = logging.getLogger(__name__)


@dataclass
class Config(object):
    mongo_uri: str
    idp_to_data_owner: Mapping[str, str]


class ScimAttributes(ResponseMicroService):
    """
    Add attributes from the scim db to the responses.
    """

    def __init__(self, config: Mapping[str, Any], internal_attributes: Dict[str, Any], *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = Config(**config)
        # Setup databases
        self.eduid_userdb = UserDB(db_uri=self.config.mongo_uri, db_name='eduid_scimapi')
        logger.info(f'Connected to eduid db: {self.eduid_userdb}')
        # TODO: Implement real 'data owner' to database lookup
        self._userdbs = {'eduid.se': ScimApiUserDB(db_uri=self.config.mongo_uri)}
        self.converter = AttributeMapper(internal_attributes)


    def process(
        self, context: satosa.context.Context, data: satosa.internal.InternalData,
    ) -> satosa.internal.InternalData:
        logger.debug(f'Data as dict:\n{pprint.pformat(data.to_dict())}')

        user = self._get_user(data)
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

        return super().process(context, data)

    def _get_user(self, data: satosa.internal.InternalData) -> Optional[ScimApiUser]:
        data_owner = self.config.idp_to_data_owner.get(data.auth_info.issuer)
        logger.debug(f'Data owner for IdP {data.auth_info.issuer}: {data_owner}')
        if not data_owner:
            return None
        userdb = self._userdbs.get(data_owner)
        if not userdb:
            logger.error(f'Found no userdb for data owner {data_owner}')
            return None
        if 'edupersonprincipalname' in data.attributes:
            eppn = data.attributes['edupersonprincipalname'][0]
            user = userdb.get_user_by_external_id(eppn)
            if user:
                logger.info(f'Found SCIM user {user.scim_id} using eppn {eppn} (data owner: {data_owner})')
            else:
                logger.info(f'No user found using eppn {eppn}')
            return user
        return None
