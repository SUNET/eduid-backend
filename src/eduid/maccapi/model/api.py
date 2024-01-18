from pydantic import BaseModel
from typing import List, Optional

class ApiUser(BaseModel):
    eppn: str
    given_name: str
    surname: str
    password: Optional[str]

class UserListResponse(BaseModel):
    status: str
    users: List[ApiUser]

class UserCreateRequest(BaseModel):
    given_name: str
    surname: str

class UserCreatedResponse(BaseModel):
    status: str
    user: ApiUser

class UserRemoveRequest(BaseModel):
    eppn: str

class UserRemovedResponse(BaseModel):
    status: str
    user: Optional[ApiUser]

class UserResetPasswordRequest(BaseModel):
    eppn: str

class UserResetPasswordResponse(BaseModel):
    status: str
    user: Optional[ApiUser]
    