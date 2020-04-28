# -*- coding: utf-8 -*-
from __future__ import annotations

from abc import ABC
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from neo4j import Driver, GraphDatabase, basic_auth

__author__ = 'lundberg'


class Neo4jDB(object):
    """Simple wrapper to allow us to define the api"""

    def __init__(self, db_uri: str, config: Optional[Dict[str, Any]] = None):
        if not db_uri:
            raise ValueError('db_uri not supplied')

        if not config:
            config = dict()

        # Parse db_uri to allow user:password@ in uri
        parse_result = urlparse(db_uri)
        self._schema = parse_result.scheme
        self._hostname = parse_result.hostname
        self._port = parse_result.port
        self._db_uri = f'{self._schema}://{self._hostname}:{self._port}'

        # Use username and password from uri if auth not in config
        self._username = parse_result.username
        if 'auth' not in config:
            config['auth'] = basic_auth(self._username, parse_result.password)

        self._driver = GraphDatabase.driver(self._db_uri, **config)

    def __repr__(self) -> str:
        return f'<eduID {self.__class__.__name__}: {getattr(self, "_username", None)}@{getattr(self, "_db_uri", None)}>'

    def count_nodes(self, label: Optional[str] = None) -> int:
        match_statement = 'MATCH ()'
        if label:
            match_statement = f'MATCH(:{label})'
        q = f"""
             {match_statement}
             RETURN count(*) as count
             """
        with self.driver.session() as session:
            return session.run(q).single()['count']

    @property
    def db_uri(self) -> str:
        return self._db_uri

    @property
    def sanitized_uri(self) -> str:
        return f'{self._schema}://{self._username}:secret@{self._hostname}:{self._port}'

    @property
    def driver(self) -> Driver:
        return self._driver

    def close(self):
        self.driver.close()


class BaseGraphDB(ABC):
    """Base class for common db operations"""

    def __init__(self, db_uri: str, scope: str, config: Optional[Dict[str, Any]] = None):
        self._db_uri = db_uri
        self._db = Neo4jDB(db_uri=self._db_uri, config=config)
        self._scope = scope
        self.db_setup()

    def __repr__(self) -> str:
        return f'<eduID {self.__class__.__name__}: {self._db.sanitized_uri}>'

    @property
    def db(self):
        return self._db

    @property
    def scope(self):
        return self._scope

    def db_setup(self):
        """Use this for setting up indices or constraints"""
        raise NotImplementedError()
