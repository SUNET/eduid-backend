from eduid.common.fastapi.context_request import Context, ContextRequestRoute


class MaccAPIContext(Context):
    manager_eppn: str | None = None
    data_owner: str | None = None


class MaccAPIRoute(ContextRequestRoute):
    contextClass = MaccAPIContext
