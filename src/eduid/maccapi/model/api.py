from typing import List, Optional

from pydantic import BaseModel


class ApiUser(BaseModel):
    eppn: str
    given_name: str
    surname: str
    password: Optional[str]


class ApiResponseBaseModel(BaseModel):
    status: str
    scope: str


class UserListResponse(ApiResponseBaseModel):
    users: List[ApiUser]


class UserCreateRequest(BaseModel):
    given_name: str
    surname: str


class UserCreatedResponse(ApiResponseBaseModel):
    user: ApiUser


class UserRemoveRequest(BaseModel):
    eppn: str


class UserRemovedResponse(ApiResponseBaseModel):
    user: Optional[ApiUser]


class UserResetPasswordRequest(BaseModel):
    eppn: str


class UserResetPasswordResponse(ApiResponseBaseModel):
    user: Optional[ApiUser]
