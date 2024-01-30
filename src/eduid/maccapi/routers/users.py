from fastapi import APIRouter, Request

from eduid.common.utils import generate_password
from eduid.maccapi.helpers import (
    UnableToAddPassword,
    create_and_sync_user,
    deactivate_user,
    get_user,
    list_users,
    replace_password,
)
from eduid.maccapi.model.api import (
    ApiUser,
    UserCreatedResponse,
    UserCreateRequest,
    UserListResponse,
    UserRemovedResponse,
    UserRemoveRequest,
    UserResetPasswordRequest,
    UserResetPasswordResponse,
)
from eduid.maccapi.util import make_presentable_password
from eduid.userdb.exceptions import UserDoesNotExist
from eduid.userdb.maccapi import ManagedAccount

users_router = APIRouter(prefix="/Users")


@users_router.get("/", response_model_exclude_none=True)
async def get_users(request: Request) -> UserListResponse:
    """
    return all users that the calling user has access to in current context
    """
    manages_accounts = list_users(context=request.app.context)

    users = [ApiUser(eppn=user.eppn, given_name=user.given_name, surname=user.surname) for user in manages_accounts]

    response = UserListResponse(status="success", scope=request.app.context.config.default_eppn_scope, users=users)

    return response


@users_router.post("/create", response_model_exclude_none=True)
async def add_user(request: Request, create_request: UserCreateRequest) -> UserCreatedResponse:
    """
    add a new user to the current context
    """
    request.app.context.logger.debug(f"add_user request: {create_request}")

    password = generate_password()
    presentable_password = make_presentable_password(password)

    managed_account: ManagedAccount = create_and_sync_user(
        context=request.app.context,
        given_name=create_request.given_name,
        surname=create_request.surname,
        password=presentable_password,
    )

    request.app.context.logger.debug(f"created managed_account: {managed_account.to_dict()}")

    response = UserCreatedResponse(
        status="success",
        scope=request.app.context.config.default_eppn_scope,
        user=ApiUser(
            eppn=managed_account.eppn,
            given_name=managed_account.given_name,
            surname=managed_account.surname,
            password=password,
        ),
    )
    request.app.context.logger.debug(f"add_user response: {response}")
    request.app.context.stats.count("maccapi_create_user_success")
    return response


@users_router.post("/remove", response_model_exclude_none=True)
async def remove_user(request: Request, remove_request: UserRemoveRequest) -> UserRemovedResponse:
    """
    remove a user from the current context
    """

    request.app.context.logger.debug(f"remove_user: {remove_request}")

    try:
        managed_account: ManagedAccount = deactivate_user(context=request.app.context, eppn=remove_request.eppn)
        api_user = ApiUser(
            eppn=managed_account.eppn, given_name=managed_account.given_name, surname=managed_account.surname
        )
        response = UserRemovedResponse(
            status="success", scope=request.app.context.config.default_eppn_scope, user=api_user
        )
        request.app.context.stats.count("maccapi_remove_user_success")
    except UserDoesNotExist as e:
        request.app.context.logger.error(f"remove_user error: {e}")
        response = UserRemovedResponse(
            status="error",
            scope=request.app.context.config.default_eppn_scope,
        )
        request.app.context.stats.count("maccapi_remove_user_error")

    return response


@users_router.post("/reset_password")
async def reset_password(request: Request, reset_request: UserResetPasswordRequest) -> UserResetPasswordResponse:
    """
    reset a user's password
    """
    request.app.context.logger.debug(f"reset_password: {reset_request}")

    eppn = reset_request.eppn
    new_password = generate_password()
    presentable_password = make_presentable_password(new_password)
    try:
        managed_account = get_user(context=request.app.context, eppn=eppn)
        replace_password(context=request.app.context, eppn=eppn, new_password=new_password)
        api_user = ApiUser(
            eppn=managed_account.eppn,
            given_name=managed_account.given_name,
            surname=managed_account.surname,
            password=presentable_password,
        )
        response = UserResetPasswordResponse(
            status="success", scope=request.app.context.config.default_eppn_scope, user=api_user
        )
        request.app.context.stats.count("maccapi_reset_password_success")
    except (UserDoesNotExist, UnableToAddPassword) as e:
        request.app.context.logger.error(f"reset_password error: {e}")
        response = UserResetPasswordResponse(
            status="error",
            scope=request.app.context.config.default_eppn_scope,
        )
        request.app.context.stats.count("maccapi_reset_password_error")

    return response
