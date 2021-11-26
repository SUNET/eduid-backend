# -*- coding: utf-8 -*-
import logging
from datetime import datetime
from typing import Dict, Optional

import requests
from pydantic import AnyHttpUrl, BaseModel, Field

__author__ = 'lundberg'

from eduid.common.utils import urlappend

logger = logging.getLogger(__name__)


class LadokClientException(Exception):
    pass


class Error(BaseModel):
    id: Optional[str]
    detail: Optional[str]


class UniversityName(BaseModel):
    long_name_sv: Optional[str]
    long_name_en: Optional[str]


class UniversityInfoData(BaseModel):
    names: Dict[str, UniversityName] = Field(alias='school_names')


class UniversityInfoResponse(BaseModel):
    data: UniversityInfoData
    error: Optional[Error]


class StudentInfoData(BaseModel):
    external_student_uid: Optional[str] = Field(alias='ladok_externt_uid')
    esi: Optional[str]
    is_student: Optional[bool]
    student_until: Optional[datetime] = Field(alias='expire_student')


class StudentInfoResponse(BaseModel):
    data: StudentInfoData
    error: Optional[Error]


class LadokClientConfig(BaseModel):
    url: AnyHttpUrl
    version: int = 1


class LadokClient:
    def __init__(self, config: LadokClientConfig):
        self.config = config
        self.base_endpoint = urlappend(self.config.url, '/api/v{self.config.version}')
        self.universities = self.load_universities()

    def load_universities(self) -> UniversityInfoData:
        """
         path: /api/v1/schoolinfo
         reply:
         {
           “data”: {
             “school_names”: {
               “ab”: {
                 “long_name_sv”: “University Name”,
                 “long_name_en”: “”
               },
               “cd”: {
                 “long_name_sv”: “Another University Name”,
                 “long_name_en”: “”
               }
             }
           },
           “error”: null
         }
        """
        endpoint = urlappend(self.base_endpoint, 'schoolinfo')

        response = requests.get(endpoint)
        if response.status_code != 200:
            logger.error(f'endpoint {endpoint} returned status code: {response.status_code}')
            raise LadokClientException('could not load universities')

        universities_response = UniversityInfoResponse(**response.json())
        if universities_response.error is not None:
            logger.error(f'endpoint {endpoint} returned error: {universities_response.error}')
            raise LadokClientException('could not load universities')
        return universities_response.data

    def student_info(self, university_abbr: str, nin: str) -> Optional[StudentInfoData]:
        """
         path: /api/v1/kf/ladokinfo
         Request body:
         {
            “data”: {
              “nin”: “string”
            }
         }
         Reply:
         {
           “data”: {
             “esi”: “urn:schac:personalUniqueCode:int:esi:ladok.se:externtstudentuid-857c0573-...",
             “is_student”: false,
             “expire_student”: “0001-01-01T00:00:00Z”
           },
           “error”: null
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

        student_response = StudentInfoResponse(**response.json())
        if student_response.error is not None:
            logger.error(f'endpoint {endpoint} returned error: {student_response.error.id}')
            logger.debug(f'error detail: {student_response.error.detail}')
            return None

        return student_response.data
