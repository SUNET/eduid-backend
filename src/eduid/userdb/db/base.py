import copy
import logging
from collections.abc import Mapping
from typing import Any, NewType

from pymongo.uri_parser import parse_uri

logger = logging.getLogger(__name__)
extra_logger = logger.getChild("extra_debug")

__author__ = "lundberg"

TUserDbDocument = NewType("TUserDbDocument", dict[str, Any])


class BaseMongoDB:
    """Simple wrapper to get pymongo real objects from the settings uri"""

    def __init__(
        self,
        db_uri: str,
        db_name: str | None = None,
        **kwargs: Any,
    ) -> None:
        if db_uri is None:
            raise ValueError("db_uri not supplied")

        self._db_uri: str = db_uri
        self._database_name: str | None = db_name
        self._sanitized_uri: str | None = None

        self._parsed_uri = parse_uri(db_uri)

        if self._parsed_uri.get("database") is None:
            self._parsed_uri["database"] = db_name

        parsed_kwargs = self._parse_kwargs(**kwargs)
        self._db_uri = _format_mongodb_uri(self._parsed_uri)
        self.db_args = dict(
            host=self._db_uri,
            tz_aware=True,
            # TODO: switch uuidRepresentation to "standard" when we made sure all UUIDs are stored as strings
            uuidRepresentation="pythonLegacy",
            **parsed_kwargs,
        )

    def _parse_kwargs(self, **kwargs: Any) -> dict[Any, Any]:
        if "replicaSet" in kwargs and kwargs["replicaSet"] is None:
            del kwargs["replicaSet"]

        _options = self._parsed_uri.get("options")
        assert _options is not None  # please mypy

        if "replicaSet" in _options and _options["replicaSet"] is not None:
            kwargs["replicaSet"] = _options["replicaSet"]

        if "replicaSet" in kwargs:
            if "socketTimeoutMS" not in kwargs:
                kwargs["socketTimeoutMS"] = 5000
            if "connectTimeoutMS" not in kwargs:
                kwargs["connectTimeoutMS"] = 5000
        return kwargs

    def __repr__(self) -> str:
        return "<eduID {!s}: {!s} {!s}>".format(
            self.__class__.__name__, getattr(self, "sanitized_uri", None), getattr(self, "_database_name", None)
        )

    __str__ = __repr__

    @property
    def sanitized_uri(self) -> str:
        """
        Return the database URI we're using in a format sensible for logging etc.

        :return: db_uri
        """
        if self._sanitized_uri is None:
            _parsed = copy.copy(self._parsed_uri)
            if "username" in _parsed:
                _parsed["password"] = "secret"
            _parsed["nodelist"] = [_parsed["nodelist"][0]]
            self._sanitized_uri = _format_mongodb_uri(_parsed)
        return self._sanitized_uri


def _format_mongodb_uri(parsed_uri: Mapping[str, Any]) -> str:
    """
    Painstakingly reconstruct a MongoDB URI parsed using pymongo.uri_parser.parse_uri.

    :param parsed_uri: Result of pymongo.uri_parser.parse_uri

    :return: New URI
    """
    MONGODB_DEFAULT_PORT = 27017

    user_pass = ""
    if parsed_uri.get("username") and parsed_uri.get("password"):
        user_pass = "{username!s}:{password!s}@".format(**parsed_uri)

    _nodes: list[str] = []
    for host, port in parsed_uri.get("nodelist", []):
        if ":" in host and not host.endswith("]"):
            # IPv6 address without brackets
            host = f"[{host!s}]"
        if port == MONGODB_DEFAULT_PORT:
            _nodes.append(host)
        else:
            _nodes.append(f"{host!s}:{port!s}")
    nodelist = ",".join(_nodes)

    _opt_list: list[str] = []
    for key, value in parsed_uri.get("options", {}).items():
        if isinstance(value, bool):
            value = str(value).lower()
        _opt_list.append(f"{key!s}={value!s}")

    options = ""
    if _opt_list:
        options = "?" + "&".join(sorted(_opt_list))

    db_name = parsed_uri.get("database") or ""

    # collection is ignored
    res = f"mongodb://{user_pass!s}{nodelist!s}/{db_name!s}{options!s}"
    return res
