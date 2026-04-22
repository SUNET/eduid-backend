__author__ = "lundberg"


from eduid.common.config.base import DataOwnerName
from eduid.common.fastapi.context_request import Context, ContextRequest, ContextRequestRoute
from eduid.userdb.scimapi import ScimApiEventDB, ScimApiGroupDB
from eduid.userdb.scimapi.invitedb import ScimApiInviteDB
from eduid.userdb.scimapi.userdb import ScimApiUserDB


class ScimApiContext(Context):
    data_owner: DataOwnerName | None = None
    userdb: ScimApiUserDB | None = None
    groupdb: ScimApiGroupDB | None = None
    invitedb: ScimApiInviteDB | None = None
    eventdb: ScimApiEventDB | None = None

    def require_data_owner(self) -> DataOwnerName:
        if self.data_owner is None:
            raise RuntimeError("data_owner not initialised")
        return self.data_owner

    def require_userdb(self) -> ScimApiUserDB:
        if self.userdb is None:
            raise RuntimeError("userdb not initialised")
        return self.userdb

    def require_groupdb(self) -> ScimApiGroupDB:
        if self.groupdb is None:
            raise RuntimeError("groupdb not initialised")
        return self.groupdb

    def require_invitedb(self) -> ScimApiInviteDB:
        if self.invitedb is None:
            raise RuntimeError("invitedb not initialised")
        return self.invitedb

    def require_eventdb(self) -> ScimApiEventDB:
        if self.eventdb is None:
            raise RuntimeError("eventdb not initialised")
        return self.eventdb


class ScimApiRequest(ContextRequest[ScimApiContext]):
    """Concrete subclass so FastAPI's param inspector sees a plain Request subclass."""


class ScimApiRoute(ContextRequestRoute):
    contextClass = ScimApiContext
