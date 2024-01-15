from fastapi import APIRouter, Request
from eduid.maccapi.helpers import create_and_sync_user, deactivate_user, list_users, replace_password

from eduid.maccapi.model.api import ApiUser, UserListResponse, UserCreateRequest, UserCreatedResponse, UserRemoveRequest, UserRemovedResponse, UserResetPasswordRequest, UserResetPasswordResponse
from eduid.maccapi.model.user import ManagedAccount
from eduid.maccapi.util import generate_password

users_router = APIRouter(prefix="/Users")

@users_router.get("/", response_model_exclude_none=True)
async def get_users(request: Request) -> UserListResponse:
    """
    return all users that the calling user has access to in current context
    """
    manages_accounts = list_users(context=request.app.context)

    users = [ApiUser(eppn=user.eppn, given_name=user.given_name, surname=user.surname) for user in manages_accounts]

    response = UserListResponse(status="success", users=users)
    
    return response


@users_router.post("/create", response_model_exclude_none=True)
async def add_user(request: Request, create_request: UserCreateRequest) -> UserCreatedResponse:
    """
    add a new user to the current context
    """
    request.app.context.logger.debug(f"add_user request: {create_request}")
    
    password = generate_password()

    managed_account: ManagedAccount = create_and_sync_user(context=request.app.context, given_name=create_request.given_name, surname=create_request.surname, password=password)

    request.app.context.logger.debug(f"created managed_account: {managed_account.to_dict()}")

    response = UserCreatedResponse(status="success", user=ApiUser(eppn=managed_account.eppn, given_name=managed_account.given_name, surname=managed_account.surname, password=password))
    request.app.context.logger.debug(f"add_user response: {response}")
    return response

@users_router.post("/remove", response_model_exclude_none=True)
async def remove_user(request: Request, remove_request: UserRemoveRequest) -> UserRemovedResponse:
    """
    remove a user from the current context
    """

    request.app.context.logger.debug(f"remove_user: {remove_request}")
 
    try:
        managed_account: ManagedAccount = deactivate_user(context=request.app.context, eppn=remove_request.eppn)
        api_user = ApiUser(eppn=managed_account.eppn, given_name=managed_account.given_name, surname=managed_account.surname)
        response = UserRemovedResponse(status="success", user=api_user)
    except Exception as e:
        request.app.context.logger.error(f"remove_user error: {e}")
        response = UserRemovedResponse(status="error")
    
    return response

@users_router.post("/reset_password")
async def reset_password(request: Request, reset_request: UserResetPasswordRequest) -> UserResetPasswordResponse:
    """
    reset a user's password
    """
    request.app.context.logger.debug(f"reset_password: {reset_request}")

    new_password = generate_password()

    try:
        replace_password(context=request.app.context, eppn=reset_request.eppn, new_password=new_password)
    except Exception as e:
        request.app.context.logger.error(f"reset_password error: {e}")
        response = UserResetPasswordResponse(status="error")
        return response

    response = UserResetPasswordResponse(status="success", password=new_password)
    return response