from typing import Union

from falcon import Request

from eduid_scimapi.context import Context
from eduid_scimapi.db.groupdb import ScimApiGroup
from eduid_scimapi.db.invitedb import ScimApiInvite
from eduid_scimapi.db.userdb import ScimApiUser
from eduid_scimapi.utils import make_etag, urlappend


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


class SCIMResource(BaseResource):
    def _check_version(self, req: Request, db_obj: Union[ScimApiGroup, ScimApiUser, ScimApiInvite]) -> bool:
        if req.headers.get('IF-MATCH') == make_etag(db_obj.version):
            return True
        self.context.logger.error(f'Version mismatch')
        self.context.logger.debug(f'{req.headers.get("IF-MATCH")} != {make_etag(db_obj.version)}')
        return False
