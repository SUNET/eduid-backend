# -*- coding: utf-8 -*-
from __future__ import annotations

import atexit
import logging
import random
import subprocess
import time
import unittest
from os import environ
from typing import Optional

from neo4j.exceptions import ServiceUnavailable

from eduid_graphdb.db import Neo4jDB

__author__ = 'lundberg'

# Run tests with different Neo4j docker image versions using environment variables
NEO4J_VERSION = environ.get('NEO4J_VERSION', 'enterprise')

logger = logging.getLogger(__name__)
logger.info(f'NEO4J_VERSION={NEO4J_VERSION}')


class Neo4jTemporaryInstance(object):
    """
    Singleton to manage a temporary Neo4j instance

    Use this for testing purpose only. The instance is automatically destroyed
    at the end of the program.

    """

    _instance: Optional[Neo4jTemporaryInstance] = None
    _http_port: int
    _https_port: int
    _bolt_port: int

    DEFAULT_USERNAME = 'neo4j'
    DEFAULT_PASSWORD = 'testing'

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
            atexit.register(cls._instance.shutdown)
        return cls._instance

    def __init__(self, neo4j_version=NEO4J_VERSION):
        self._http_port = random.randint(40000, 43000)
        self._https_port = random.randint(44000, 46000)
        self._bolt_port = random.randint(47000, 50000)
        self._docker_exc = 'docker'
        self._docker_name = 'neo4j-{!s}'.format(self.bolt_port)
        try:
            self._process = subprocess.Popen(
                [
                    self._docker_exc,
                    'run',
                    '--rm',
                    '--name',
                    f'{self._docker_name}',
                    '-p',
                    f'{self.http_port}:7474',
                    '-p',
                    f'{self.https_port}:7473',
                    '-p',
                    f'{self.bolt_port}:7687',
                    '-e',
                    f'NEO4J_AUTH={self.DEFAULT_USERNAME}/{self.DEFAULT_PASSWORD}',
                    '-e',
                    'NEO4J_ACCEPT_LICENSE_AGREEMENT=yes',
                    f'neo4j:{neo4j_version}',
                ],
                stdout=open('/tmp/neo4j-temp.log', 'wb'),
                stderr=subprocess.STDOUT,
            )
        except OSError:
            assert False, "No docker executable found"

        self._host = 'localhost'

        self._db = None
        for i in range(300):
            time.sleep(0.5)
            try:
                db_uri = f'bolt://{self.DEFAULT_USERNAME}:{self.DEFAULT_PASSWORD}@{self.host}:{self.bolt_port}'
                self._db = Neo4jDB(db_uri=db_uri, config={'encrypted': False})
            except (ServiceUnavailable, ConnectionError) as e:
                logger.error(e)
                logger.info(f'Retrying, attempt {i}')
                continue
            else:
                logger.info(f'Successfully connected to neo4jdb on attempt {i} after {i*0.5}s')
                break

        if self._db is None:
            self.shutdown()
            assert False, 'Cannot connect to the neo4j test instance'

    @property
    def db(self):
        return self._db

    @property
    def host(self):
        return self._host

    @property
    def http_port(self):
        return self._http_port

    @property
    def https_port(self):
        return self._https_port

    @property
    def bolt_port(self):
        return self._bolt_port

    def purge_db(self):
        q = """
            MATCH (n)
            DETACH DELETE n
            """
        with self.db.driver.session() as s:
            s.run(q)
            # Drop constraints and indices
            for constraint in s.run("CALL db.constraints"):
                s.run(f'DROP CONSTRAINT {constraint["name"]}')
            for index in s.run("CALL db.indexes"):
                s.run(f'DROP INDEX {index["name"]}')

    def shutdown(self):
        if self._process:
            self._process.terminate()
            self._process.wait()
            self._process = None


class Neo4jTestCase(unittest.TestCase):
    """
    Base test case that sets up a temporary Neo4j instance
    """

    neo4j_instance: Neo4jTemporaryInstance
    neo4jdb: Neo4jDB

    @classmethod
    def setUpClass(cls) -> None:
        cls.neo4j_instance = Neo4jTemporaryInstance.get_instance()
        cls.neo4jdb = cls.neo4j_instance.db

    def tearDown(self):
        self.neo4j_instance.purge_db()
