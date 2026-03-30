import os
from http import HTTPStatus
from typing import Any

import pytest
from fastapi.testclient import TestClient

from eduid.userdb.testing import MongoTemporaryInstance
from eduid.workers.job_runner.app import init_app


class JobRunnerStatusTestCase:
    mongodb_instance: MongoTemporaryInstance

    @pytest.fixture(autouse=True)
    def setup_mongodb(self, mongo_instance: MongoTemporaryInstance) -> None:
        self.mongodb_instance = mongo_instance

    def _get_config(self) -> dict[str, Any]:
        return {
            "mongo_uri": self.mongodb_instance.uri,
            "testing": True,
            "environment": "dev",
            "celery": {},
        }

    @pytest.fixture(autouse=True)
    def setup(self, setup_mongodb: None) -> None:
        if "EDUID_CONFIG_YAML" not in os.environ:
            os.environ["EDUID_CONFIG_YAML"] = "YAML_CONFIG_NOT_USED"
        os.environ["WORKER_NAME"] = "test_worker"
        self.app = init_app(name="test_job_runner", test_config=self._get_config())
        self.client = TestClient(self.app)


class TestStatus(JobRunnerStatusTestCase):
    def test_status_ping(self) -> None:
        response = self.client.get("/status/ping")
        assert response.status_code == HTTPStatus.OK
        assert response.content == b""

    def test_status_healthy_ok(self) -> None:
        response = self.client.get("/status/healthy")
        assert response.status_code == HTTPStatus.OK
