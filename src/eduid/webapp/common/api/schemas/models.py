from collections.abc import Mapping
from enum import Enum, unique
from typing import Any

from flask import Request

from eduid.webapp.common.api.utils import get_flux_type

__author__ = "lundberg"


@unique
class FluxResponseStatus(Enum):
    OK = "ok"
    ERROR = "error"


class FluxResponse:
    """
    Class representing a Flux Standard Action (https://github.com/redux-utilities/flux-standard-action).

    Quoting the page above, an example of a basic Flux Standard Action is

        {
          type: 'ADD_TODO',
          payload: {
            text: 'Do something.'
          }
        }

    An action MUST

      - have a type property.

    An action MAY

      - have an error property.
      - have a payload property.
      - have a meta property.

    An action MUST NOT include properties other than type, payload, error, and meta.
    """

    def __init__(
        self,
        req: Request,
        payload: Mapping[str, Any] | None = None,
        error: bool | None = None,
        meta: Mapping[str, Any] | None = None,
    ) -> None:
        _suffix = "success"
        if error:
            _suffix = "fail"
        self.flux_type = get_flux_type(req, _suffix)
        self.payload = payload
        self.meta = meta
        self.error = error

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__!s} ({self.to_dict()!r})>"

    def __unicode__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        return f"{self.__class__.__name__!s} ({self.to_dict()!r})"

    def to_dict(self) -> dict[str, Any]:
        rv = dict[str, Any]()
        # A Flux Standard Action MUST have a type
        rv["type"] = self.flux_type
        # ... and MAY have payload, error, meta (and MUST NOT have anything else)
        if self.payload is not None:
            rv["payload"] = self.payload
        if self.error is not None:
            rv["error"] = self.error
        if self.meta is not None:
            rv["meta"] = self.meta
        return rv


# TODO: Do we need these different classes for fail and success?
#       FluxResponse.error already indicates if it is a failure response.


class FluxSuccessResponse(FluxResponse):
    def __init__(self, req: Request, payload: Mapping[str, Any] | None, meta: Mapping[str, Any] | None = None) -> None:
        super().__init__(req, payload, meta=meta)


class FluxFailResponse(FluxResponse):
    def __init__(self, req: Request, payload: Mapping[str, Any] | None, meta: Mapping[str, Any] | None = None) -> None:
        super().__init__(req, payload, error=True, meta=meta)
