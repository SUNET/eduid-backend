# -*- coding: utf-8 -*-
import logging
from datetime import datetime
from typing import Dict, Optional

import requests
from pydantic import AnyHttpUrl, BaseModel, Field, ValidationError

__author__ = 'lundberg'

from eduid.common.utils import urlappend

logger = logging.getLogger(__name__)


class LadokClientException(Exception):
    pass


class Error(BaseModel):
    id: Optional[str]
    detail: Optional[str] = Field(default=None, alias='details')


class LadokBaseModel(BaseModel):
    class Config:
        allow_population_by_field_name = True


class UniversityName(LadokBaseModel):
    name_sv: Optional[str] = Field(default=None, alias='long_name_sv')
    name_en: Optional[str] = Field(default=None, alias='long_name_en')


class UniversitiesData(LadokBaseModel):
    names: Dict[str, UniversityName] = Field(alias='school_names')


class UniversitiesInfoResponse(LadokBaseModel):
    data: Optional[UniversitiesData]
    error: Optional[Error]


class LadokUserInfo(LadokBaseModel):
    external_id: str = Field(alias='ladok_externt_uid')
    esi: Optional[str]
    is_student: Optional[bool]
    student_until: Optional[datetime] = Field(default=None, alias='expire_student')


class LadokUserInfoResponse(LadokBaseModel):
    data: Optional[LadokUserInfo]
    error: Optional[Error]


class LadokClientConfig(LadokBaseModel):
    url: AnyHttpUrl
    version: int = 1


class LadokClient:
    def __init__(self, config: LadokClientConfig):
        self.config = config
        self.base_endpoint = urlappend(self.config.url, '/api/v{self.config.version}')
        self.universities = self.load_universities()

    def load_universities(self) -> UniversitiesData:
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
        endpoint = urlappend(self.base_endpoint, 'schoolinfo')

        response = requests.get(endpoint)
        if response.status_code != 200:
            logger.error(f'endpoint {endpoint} returned status code: {response.status_code}')
            raise LadokClientException('could not load universities')

        universities_response = UniversitiesInfoResponse(**response.json())
        if universities_response.error is not None:
            logger.error(f'endpoint {endpoint} returned error: {universities_response.error}')
            raise LadokClientException('could not load universities')
        assert universities_response.data is not None  # please mypy
        return universities_response.data

    def get_user_info(self, university_abbr: str, nin: str) -> Optional[LadokUserInfo]:
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
        if university_abbr not in self.universities.names:
            raise LadokClientException(f'university with abbreviation {university_abbr} not found')

        service_path = f'{university_abbr}/ladokinfo'
        endpoint = urlappend(self.base_endpoint, service_path)

        response = requests.post(endpoint, json={'nin': nin})
        if response.status_code != 200:
            logger.error(f'endpoint {endpoint} returned status code: {response.status_code}')
            return None

        try:
            user_response = LadokUserInfoResponse(**response.json())
        except ValidationError as e:
            logger.error(f'could not validate response from {endpoint}: {e}')
            logger.debug(f'university_abbr: {university_abbr}, nin: {nin}')
            logger.debug(f'response.json: {response.json()}')
            return None

        if user_response.error is not None:
            logger.error(f'endpoint {endpoint} returned error: {user_response.error.id}')
            logger.debug(f'error detail: {user_response.error.detail}')
            return None

        return user_response.data