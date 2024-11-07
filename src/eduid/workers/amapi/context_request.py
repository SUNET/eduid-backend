__author__ = "masv"

from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from fastapi.routing import APIRoute
from starlette.requests import Request, empty_receive, empty_send
from starlette.responses import Response
from starlette.types import Receive, Scope, Send


@dataclass
class Context:
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ContextRequest(Request):
    def __init__(self, scope: Scope, receive: Receive = empty_receive, send: Send = empty_send) -> None:
        super().__init__(scope=scope, receive=receive, send=send)

    @property
    def context(self) -> Context:
        try:
            return self.state.context
        except AttributeError:
            # Lazy init of self.state.context
            self.state.context = Context()
            return self.context

    @context.setter
    def context(self, context: Context) -> None:
        self.state.context = context


class ContextRequestMixin:
    @staticmethod
    def make_context_request(request: Request | ContextRequest) -> ContextRequest:
        if not isinstance(request, ContextRequest):
            request = ContextRequest(request.scope, request.receive)
        return request


class ContextRequestRoute(APIRoute, ContextRequestMixin):
    """
    Make ContextRequest the default request class
    """

    def get_route_handler(self) -> Callable:
        original_route_handler = super().get_route_handler()

        async def context_route_handler(request: Request | ContextRequest) -> Response:
            request = self.make_context_request(request)
            return await original_route_handler(request)

        return context_route_handler
