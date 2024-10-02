from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from fastapi import Request, Response
from fastapi.routing import APIRoute


@dataclass
class Context:
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ContextRequest(Request):
    def __init__(self, context_class: type[Context], *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.contextClass = context_class

    @property
    def context(self) -> Context:
        try:
            return self.state.context
        except AttributeError:
            # Lazy init of self.state.context
            self.state.context = self.contextClass()
            return self.context

    @context.setter
    def context(self, context: Context):
        self.state.context = context


class ContextRequestMixin:
    @staticmethod
    def make_context_request(request: Request | ContextRequest, context_class: type[Context]) -> ContextRequest:
        if not isinstance(request, ContextRequest):
            request = ContextRequest(context_class=context_class, scope=request.scope, receive=request.receive)
        return request


class ContextRequestRoute(APIRoute, ContextRequestMixin):
    """
    Make ContextRequest the default request class
    """

    # Override in subclass to change the default context class
    contextClass: type[Context] = Context

    def get_route_handler(self) -> Callable:
        original_route_handler = super().get_route_handler()

        async def context_route_handler(request: Request | ContextRequest) -> Response:
            request = self.make_context_request(request=request, context_class=self.contextClass)
            return await original_route_handler(request)

        return context_route_handler
