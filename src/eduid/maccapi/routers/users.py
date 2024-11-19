from fastapi import APIRouter, Response, status

from eduid.common.fastapi.context_request import ContextRequest
from eduid.common.utils import generate_password
from eduid.maccapi.context_request import MaccAPIContext, MaccAPIRoute
from eduid.maccapi.helpers import (
    UnableToAddPassword,
    add_api_event,
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

users_router = APIRouter(route_class=MaccAPIRoute, prefix="/Users")


@users_router.get("/", response_model_exclude_none=True)
async def get_users(request: ContextRequest) -> UserListResponse:
    """
    return all users that the calling user has access to in current context
    """

    assert isinstance(request.context, MaccAPIContext)  # please mypy
    assert request.context.data_owner is not None  # please mypy
    managed_accounts = list_users(context=request.app.context, data_owner=request.context.data_owner)

    users = [ApiUser(eppn=user.eppn, given_name=user.given_name, surname=user.surname) for user in managed_accounts]

    response = UserListResponse(status="success", scope=request.app.context.config.default_eppn_scope, users=users)

    return response


@users_router.post("/create", response_model_exclude_none=True)
async def add_user(
    request: ContextRequest, create_request: UserCreateRequest, response: Response
) -> UserCreatedResponse:
    """
    add a new user to the current context
    """
    request.app.context.logger.debug(f"add_user request: {create_request}")

    password = generate_password()
    presentable_password = make_presentable_password(password)

    assert isinstance(request.context, MaccAPIContext)  # please mypy
    assert request.context.data_owner is not None  # please mypy
    assert request.context.manager_eppn is not None  # please mypy
    managed_account: ManagedAccount = create_and_sync_user(
        context=request.app.context,
        data_owner=request.context.data_owner,
        given_name=create_request.given_name,
        surname=create_request.surname,
        password=password,
    )

    request.app.context.logger.debug(f"created managed_account: {managed_account.to_dict()}")

    add_api_event(
        context=request.app.context,
        eppn=managed_account.eppn,
        action="created user",
        action_by=request.context.manager_eppn,
        data_owner=request.context.data_owner,
    )

    add_user_response = UserCreatedResponse(
        status="success",
        scope=request.app.context.config.default_eppn_scope,
        user=ApiUser(
            eppn=managed_account.eppn,
            given_name=managed_account.given_name,
            surname=managed_account.surname,
            password=presentable_password,
        ),
    )
    request.app.context.logger.debug(f"add_user response: {add_user_response}")
    request.app.context.stats.count("maccapi_create_user_success")
    response.status_code = status.HTTP_201_CREATED
    return add_user_response


@users_router.post("/remove", response_model_exclude_none=True)
async def remove_user(
    request: ContextRequest, remove_request: UserRemoveRequest, response: Response
) -> UserRemovedResponse:
    """
    remove a user from the current context
    """

    request.app.context.logger.debug(f"remove_user: {remove_request}")

    try:
        assert isinstance(request.context, MaccAPIContext)  # please mypy
        assert request.context.data_owner is not None  # please mypy
        assert request.context.manager_eppn is not None  # please mypy
        managed_account: ManagedAccount = deactivate_user(
            context=request.app.context, eppn=remove_request.eppn, data_owner=request.context.data_owner
        )

        add_api_event(
            context=request.app.context,
            eppn=remove_request.eppn,
            action="deactivated user",
            action_by=request.context.manager_eppn,
            data_owner=request.context.data_owner,
        )

        api_user = ApiUser(
            eppn=managed_account.eppn, given_name=managed_account.given_name, surname=managed_account.surname
        )
        remove_user_response = UserRemovedResponse(
            status="success", scope=request.app.context.config.default_eppn_scope, user=api_user
        )
        request.app.context.stats.count("maccapi_remove_user_success")
    except UserDoesNotExist as e:
        request.app.context.logger.error(f"remove_user error: {e} - user already removed")
        remove_user_response = UserRemovedResponse(
            status="success",
            scope=request.app.context.config.default_eppn_scope,
        )
        request.app.context.stats.count("maccapi_remove_user_error")

    return remove_user_response


@users_router.post("/reset_password")
async def reset_password(
    request: ContextRequest, reset_request: UserResetPasswordRequest, response: Response
) -> UserResetPasswordResponse:
    """
    reset a user's password
    """
    request.app.context.logger.debug(f"reset_password: {reset_request}")

    eppn = reset_request.eppn
    new_password = generate_password()
    presentable_password = make_presentable_password(new_password)
    try:
        assert isinstance(request.context, MaccAPIContext)  # please mypy
        assert request.context.data_owner is not None  # please mypy
        assert request.context.manager_eppn is not None  # please mypy
        managed_account = get_user(context=request.app.context, eppn=eppn, data_owner=request.context.data_owner)
        replace_password(context=request.app.context, eppn=eppn, new_password=new_password)

        add_api_event(
            context=request.app.context,
            eppn=reset_request.eppn,
            action="reset password for user",
            action_by=request.context.manager_eppn,
            data_owner=request.context.data_owner,
        )

        api_user = ApiUser(
            eppn=managed_account.eppn,
            given_name=managed_account.given_name,
            surname=managed_account.surname,
            password=presentable_password,
        )
        reset_password_response = UserResetPasswordResponse(
            status="success", scope=request.app.context.config.default_eppn_scope, user=api_user
        )
        request.app.context.stats.count("maccapi_reset_password_success")
    except (UserDoesNotExist, UnableToAddPassword) as e:
        request.app.context.logger.error(f"reset_password error: {e}")
        reset_password_response = UserResetPasswordResponse(
            status="error",
            scope=request.app.context.config.default_eppn_scope,
        )
        request.app.context.stats.count("maccapi_reset_password_error")
        if isinstance(e, UserDoesNotExist):
            response.status_code = status.HTTP_404_NOT_FOUND
        else:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return reset_password_response
