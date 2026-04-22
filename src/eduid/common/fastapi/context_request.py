from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any, cast

from fastapi import Request, Response
from fastapi.routing import APIRoute


@dataclass
class Context:
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ContextRequest[C: Context = Context](Request):
    def __init__(self, context_class: type[C], *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.contextClass: type[C] = context_class

    @property
    def context(self) -> C:
        try:
            return cast(C, self.state.context)
        except AttributeError:
            # Lazy init of self.state.context
            self.state.context = self.contextClass()
            return self.context

    @context.setter
    def context(self, context: C) -> None:
        self.state.context = context


class ContextRequestMixin:
    @staticmethod
    def make_context_request[C: Context](request: Request, context_class: type[C]) -> ContextRequest[C]:
        if isinstance(request, ContextRequest):
            return cast(ContextRequest[C], request)
        return ContextRequest(context_class=context_class, scope=request.scope, receive=request.receive)


class ContextRequestRoute(APIRoute, ContextRequestMixin):
    """
    Make ContextRequest the default request class
    """

    # Override in subclass to change the default context class
    contextClass: type[Context] = Context

    def get_route_handler(self) -> Callable[..., Any]:
        original_route_handler = super().get_route_handler()

        async def context_route_handler(request: Request | ContextRequest[Context]) -> Response:
            request = self.make_context_request(request=request, context_class=self.contextClass)
            return await original_route_handler(request)

        return context_route_handler
