import os
import unittest
from typing import Any, cast

import pkg_resources
from starlette.testclient import TestClient

from eduid.common.config.parsers import load_config
from eduid.maccapi.app import init_api
from eduid.maccapi.config import MAccApiConfig
from eduid.maccapi.context import Context
from eduid.userdb.testing import MongoTemporaryInstance
from eduid.vccs.client import VCCSClient
from eduid.webapp.common.authn.testing import MockVCCSClient


class BaseDBTestCase(unittest.TestCase):
    """
    Base test case that sets up a temporary database for testing.
    """

    mongodb_instance: MongoTemporaryInstance
    mongo_uri: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.mongodb_instance = MongoTemporaryInstance.get_instance()
        cls.mongo_uri = cls.mongodb_instance.uri

    def _get_config(self) -> dict[str, Any]:
        config = {
            "debug": True,
            "testing": True,
            "mongo_uri": self.mongo_uri,
            "environment": "dev",
            "data_owners": {"eduid.se": {"db_name": "eduid_se"}, "test.eduid.se": {"db_name": "test_eduid_se"}},
            "logging_config": {
                "loggers": {
                    "root": {
                        "handlers": ["console"],
                        "level": "DEBUG",
                    }
                }
            },
        }
        return config


class MAccApiTestCase(BaseDBTestCase):
    """
    Base class for tests of the MAcc API.
    """

    @classmethod
    def setUpClass(cls) -> None:
        return super().setUpClass()

    def setUp(self) -> None:
        if "EDUID_CONFIG_YAML" not in os.environ:
            os.environ["EDUID_CONFIG_YAML"] = "YAML_CONFIG_NOT_USED"

        self.datadir = pkg_resources.resource_filename(__name__, "tests/data")
        self.test_config = self._get_config()
        config = load_config(typ=MAccApiConfig, app_name="maccapi", ns="api", test_config=self.test_config)
        self.context = Context(config=config)
        self.db = self.context.db

        vccs_client = cast(VCCSClient, MockVCCSClient())

        self.api = init_api(name="test_api", test_config=self.test_config, vccs_client=vccs_client)
        self.client = TestClient(self.api)
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _get_config(self) -> dict:
        config = super()._get_config()
        config["keystore_path"] = f"{self.datadir}/testing_jwks.json"
        config["signing_key_id"] = "testing-maccapi-2106210000"
        config["authorization_mandatory"] = False
        return config

    def tearDown(self) -> None:
        super().tearDown()
        if self.db:
            self.db._drop_whole_collection()
