import logging
from collections.abc import Mapping
from datetime import datetime

import requests
from pydantic import BaseModel, ConfigDict, Field, ValidationError

__author__ = "lundberg"

from eduid.common.config.base import EduidEnvironment
from eduid.common.models.generic import HttpUrlStr
from eduid.common.utils import urlappend

logger = logging.getLogger(__name__)


class LadokClientException(Exception):
    pass


class Error(BaseModel):
    id: str | None = None
    detail: str | None = Field(default=None, alias="details")


class LadokBaseModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


class UniversityName(LadokBaseModel):
    sv: str | None = Field(default=None, alias="long_name_sv")
    en: str | None = Field(default=None, alias="long_name_en")


class UniversitiesData(LadokBaseModel):
    names: dict[str, UniversityName] = Field(alias="school_names")


class UniversitiesInfoResponse(LadokBaseModel):
    data: UniversitiesData | None = None
    error: Error | None = None


class LadokUserInfo(LadokBaseModel):
    external_id: str = Field(alias="ladok_externt_uid")
    esi: str | None = None
    is_student: bool | None = None
    student_until: datetime | None = Field(default=None, alias="expire_student")


class LadokUserInfoResponse(LadokBaseModel):
    data: LadokUserInfo | None = None
    error: Error | None = None


class LadokClientConfig(LadokBaseModel):
    url: HttpUrlStr
    version: str = "v1"
    dev_universities: dict[str, UniversityName] | None = None  # used for local development


class University(BaseModel):
    ladok_name: str
    name: UniversityName


class LadokClient:
    def __init__(self, config: LadokClientConfig, env: EduidEnvironment) -> None:
        self.config = config
        self.env = env
        self.base_endpoint = urlappend(self.config.url, f"/api/{self.config.version}")
        self.universities = self.load_universities()

    def load_universities(self) -> Mapping[str, University]:
        if self.env is EduidEnvironment.dev and self.config.dev_universities is not None:
            universities_data = self.config.dev_universities
        else:
            universities_data = self.get_universities().names

        universities = {}
        for key, value in universities_data.items():
            universities[key] = University(ladok_name=key, name=value)
        return universities

    def get_universities(self) -> UniversitiesData:
        """
        path: /api/v1/schoolinfo
        reply:
        {
          "data": {
            "school_names": {
              "ab": {
                "long_name_sv": "University Name",
                "long_name_en": ""
              },
              "cd": {
                "long_name_sv": "Another University Name",
                "long_name_en": ""
              }
            }
          },
          "error": null
        }
        """
        endpoint = urlappend(self.base_endpoint, "schoolinfo")

        response = requests.get(endpoint)
        if response.status_code != 200:
            logger.error(f"endpoint {endpoint} returned status code: {response.status_code}")
            raise LadokClientException("could not load universities")

        universities_response = UniversitiesInfoResponse(**response.json())
        if universities_response.error is not None:
            logger.error(f"endpoint {endpoint} returned error: {universities_response.error}")
            raise LadokClientException("could not load universities")
        assert universities_response.data is not None  # please mypy
        return universities_response.data

    def get_user_info(self, ladok_name: str, nin: str) -> LadokUserInfo | None:
        """
        path: /api/v1/kf/ladokinfo
        Request body:
        {
           "data": {
             "nin": "string"
           }
        }
        Reply:
        {
          "data": {
            "ladok_externt_uid" : "857c0573-..."
            "esi": "urn:schac:personalUniqueCode:int:esi:ladok.se:externtstudentuid-857c0573-...",
            "is_student": false,
            "expire_student": "0001-01-01T00:00:00Z"
          },
          "error": null
        }
        """
        if ladok_name not in self.universities:
            raise LadokClientException(f"university with Ladok name {ladok_name} not found")

        service_path = f"{ladok_name}/ladokinfo"
        endpoint = urlappend(self.base_endpoint, service_path)

        response = requests.post(endpoint, json={"data": {"nin": nin}})
        if response.status_code != 200:
            logger.error(f"endpoint {endpoint} returned status code: {response.status_code}")
            return None

        try:
            user_response = LadokUserInfoResponse(**response.json())
        except ValidationError as e:
            logger.error(f"could not validate response from {endpoint}: {e}")
            logger.debug(f"ladok_name: {ladok_name}, nin: {nin}")
            logger.debug(f"response.json: {response.json()}")
            return None

        if user_response.error is not None:
            logger.error(f"endpoint {endpoint} returned error: {user_response.error.id}")
            logger.debug(f"error detail: {user_response.error.detail}")
            return None

        return user_response.data
