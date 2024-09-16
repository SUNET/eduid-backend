from pydantic import BaseModel


class ApiUser(BaseModel):
    eppn: str
    given_name: str
    surname: str
    password: str | None = None


class ApiResponseBaseModel(BaseModel):
    status: str
    scope: str


class UserListResponse(ApiResponseBaseModel):
    users: list[ApiUser]


class UserCreateRequest(BaseModel):
    given_name: str
    surname: str


class UserCreatedResponse(ApiResponseBaseModel):
    user: ApiUser


class UserRemoveRequest(BaseModel):
    eppn: str


class UserRemovedResponse(ApiResponseBaseModel):
    user: ApiUser | None = None


class UserResetPasswordRequest(BaseModel):
    eppn: str


class UserResetPasswordResponse(ApiResponseBaseModel):
    user: ApiUser | None = None
