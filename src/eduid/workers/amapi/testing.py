from eduid.common.models.amapi_user import Reason, Source
from eduid.common.testing_base import CommonTestCase
from eduid.workers.amapi.config import EndpointRestriction
from typing import Dict, Any
import pkg_resources
from eduid.workers.amapi.app import init_api
from fastapi.testclient import TestClient
import json


class TestAMBase(CommonTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        self.path = pkg_resources.resource_filename(__name__, "tests/data")
        self.test_config = self._get_config()
        self.test_singing_key = "testing-amapi-2106210000"

        self.api = init_api(name="test_api", test_config=self.test_config)
        self.client = TestClient(self.api)

        self.eppn = "hubba-bubba"
        self.source = Source.TEST.value
        self.reason = Reason.TEST.value

    def _get_config(self) -> Dict[str, Any]:
        config = {
            "keystore_path": f"{self.path}/testing_jwks.json",
            "mongo_uri": self.settings["mongo_uri"],
            "user_restriction": {
                "test-service_name": [
                    EndpointRestriction(method="put", endpoint="/users/*/name"),
                    EndpointRestriction(method="put", endpoint="/users/*/phone"),
                    EndpointRestriction(method="put", endpoint="/users/*/email"),
                    EndpointRestriction(method="put", endpoint="/users/*/language"),
                    EndpointRestriction(method="put", endpoint="/users/*/meta/cleaned"),
                    EndpointRestriction(method="put", endpoint="/users/*/terminate"),
                ],
            },
        }
        return config

    @staticmethod
    def as_json(data: dict) -> str:
        return json.dumps(data)
