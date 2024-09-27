from collections.abc import Callable
from types import TracebackType
from typing import Any, Protocol, TypeAlias

ExcInfo: TypeAlias = tuple[type[BaseException], BaseException, TracebackType]
OptExcInfo: TypeAlias = ExcInfo | tuple[None, None, None]


class StartResponse(Protocol):
    def __call__(
        self, status: str, headers: list[tuple[str, str]], exc_info: OptExcInfo | None = ..., /
    ) -> Callable[[bytes], object]: ...


WSGIEnvironment: TypeAlias = dict[str, Any]  # stable
