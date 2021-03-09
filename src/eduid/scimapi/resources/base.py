from typing import Union
from uuid import UUID

from falcon import Request

from eduid.scimapi.context import Context
from eduid.scimapi.db.groupdb import ScimApiGroup
from eduid.scimapi.db.invitedb import ScimApiInvite
from eduid.scimapi.db.userdb import ScimApiUser
from eduid.scimapi.schemas.scimbase import SCIMResourceType
from eduid.scimapi.utils import make_etag, urlappend


class BaseResource(object):
    def __init__(self, context: Context):
        self.context = context

    def __str__(self):
        return f'{self.__class__}'

    def url_for(self, *args) -> str:
        url = self.context.base_url
        for arg in args:
            url = urlappend(url, f'{arg}')
        return url

    def resource_url(self, resource_type: SCIMResourceType, scim_id: UUID) -> str:
        return self.url_for(resource_type.value + 's', str(scim_id))


class SCIMResource(BaseResource):
    def _check_version(self, req: Request, db_obj: Union[ScimApiGroup, ScimApiUser, ScimApiInvite]) -> bool:
        if req.headers.get('IF-MATCH') == make_etag(db_obj.version):
            return True
        self.context.logger.error(f'Version mismatch')
        self.context.logger.debug(f'{req.headers.get("IF-MATCH")} != {make_etag(db_obj.version)}')
        return False
