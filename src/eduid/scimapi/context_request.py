__author__ = "lundberg"

from typing import Optional

from eduid.common.config.base import DataOwnerName
from eduid.common.fastapi.context_request import Context, ContextRequestRoute
from eduid.userdb.scimapi import ScimApiEventDB, ScimApiGroupDB
from eduid.userdb.scimapi.invitedb import ScimApiInviteDB
from eduid.userdb.scimapi.userdb import ScimApiUserDB


class ScimApiContext(Context):
    data_owner: Optional[DataOwnerName] = None
    userdb: Optional[ScimApiUserDB] = None
    groupdb: Optional[ScimApiGroupDB] = None
    invitedb: Optional[ScimApiInviteDB] = None
    eventdb: Optional[ScimApiEventDB] = None


class ScimApiRoute(ContextRequestRoute):
    contextClass = ScimApiContext
