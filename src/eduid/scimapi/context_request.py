__author__ = "lundberg"


from eduid.common.config.base import DataOwnerName
from eduid.common.fastapi.context_request import Context, ContextRequestRoute
from eduid.userdb.scimapi import ScimApiEventDB, ScimApiGroupDB
from eduid.userdb.scimapi.invitedb import ScimApiInviteDB
from eduid.userdb.scimapi.userdb import ScimApiUserDB


class ScimApiContext(Context):
    data_owner: DataOwnerName | None = None
    userdb: ScimApiUserDB | None = None
    groupdb: ScimApiGroupDB | None = None
    invitedb: ScimApiInviteDB | None = None
    eventdb: ScimApiEventDB | None = None


class ScimApiRoute(ContextRequestRoute):
    contextClass = ScimApiContext
