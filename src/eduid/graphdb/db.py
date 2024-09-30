from __future__ import annotations

from abc import ABC
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from neo4j import Driver, GraphDatabase, basic_auth

__author__ = "lundberg"


class Neo4jDB:
    """Simple wrapper to allow us to define the api"""

    def __init__(self, db_uri: str, config: Mapping[str, Any] | None = None):
        if not db_uri:
            raise ValueError("db_uri not supplied")

        if not config:
            config = dict()

        # Parse db_uri to allow user:password@ in uri
        parse_result = urlparse(db_uri)
        self._schema = parse_result.scheme
        self._hostname = parse_result.hostname
        self._port = parse_result.port
        self._routing_context = parse_result.query
        self._db_uri = f"{self._schema}://{self._hostname}:{self._port}"
        if self._routing_context:
            self._db_uri += f"?{self._routing_context}"

        # Make a copy of config to not modify the callers' data
        _config = dict(config)

        # Use username and password from uri if auth not in config
        self._username = parse_result.username
        if "auth" not in config and (self._username and parse_result.password):
            _config["auth"] = basic_auth(self._username, parse_result.password)

        self._driver = GraphDatabase.driver(self._db_uri, **_config)

    def __repr__(self) -> str:
        return f'<eduID {self.__class__.__name__}: {getattr(self, "_username", None)}@{getattr(self, "_db_uri", None)}>'

    def count_nodes(self, label: str | None = None) -> int | None:
        match_statement = "MATCH ()"
        if label:
            match_statement = f"MATCH(:{label})"
        q = f"""
             {match_statement}
             RETURN count(*) as count
             """
        with self.driver.session() as session:
            record = session.run(q).single()
            if record:
                return record["count"]
        return None

    @property
    def db_uri(self) -> str:
        return self._db_uri

    @property
    def sanitized_uri(self) -> str:
        return f"{self._schema}://{self._username}:secret@{self._hostname}:{self._port}"

    @property
    def driver(self) -> Driver:
        return self._driver

    def close(self) -> None:
        self.driver.close()


class BaseGraphDB(ABC):
    """Base class for common db operations"""

    def __init__(self, db_uri: str, config: dict[str, Any] | None = None):
        self._db_uri = db_uri
        self._db = Neo4jDB(db_uri=self._db_uri, config=config)
        self.db_setup()

    def __repr__(self) -> str:
        return f"<eduID {self.__class__.__name__}: {self._db.sanitized_uri}>"

    @property
    def db(self):
        return self._db

    def db_setup(self) -> None:
        """Use this for setting up indices or constraints"""
        raise NotImplementedError()
