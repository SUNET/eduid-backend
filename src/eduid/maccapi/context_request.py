from typing import Optional

from eduid.common.fastapi.context_request import Context, ContextRequestRoute


class MaccAPIContext(Context):
    manager_eppn: Optional[str] = None
    data_owner: Optional[str] = None


class MaccAPIRoute(ContextRequestRoute):
    contextClass = MaccAPIContext
