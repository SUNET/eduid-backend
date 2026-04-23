from eduid.common.fastapi.context_request import Context, ContextRequest, ContextRequestRoute


class MaccAPIContext(Context):
    manager_eppn: str | None = None
    data_owner: str | None = None

    def require_data_owner(self) -> str:
        if self.data_owner is None:
            raise RuntimeError("data_owner not initialised")
        return self.data_owner

    def require_manager_eppn(self) -> str:
        if self.manager_eppn is None:
            raise RuntimeError("manager_eppn not initialised")
        return self.manager_eppn


class MaccAPIRequest(ContextRequest[MaccAPIContext]):
    """Concrete subclass so FastAPI's param inspector sees a plain Request subclass."""


class MaccAPIRoute(ContextRequestRoute):
    contextClass = MaccAPIContext
