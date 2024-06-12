from typing import Optional

from flask import Blueprint

from eduid.userdb import User
from eduid.userdb.exceptions import UserOutOfSync
from eduid.userdb.personal_data import PersonalDataUser
from eduid.userdb.user import UserSettings
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.personal_data.app import current_pdata_app as current_app
from eduid.webapp.personal_data.helpers import PDataMsg, is_valid_chosen_given_name
from eduid.webapp.personal_data.schemas import (
    AllDataResponseSchema,
    IdentitiesResponseSchema,
    PersonalDataRequestSchema,
    PersonalDataResponseSchema,
    UserSettingsRequestSchema,
    UserSettingsResponseSchema,
)

pd_views = Blueprint("personal_data", __name__, url_prefix="")


@pd_views.route("/all-user-data", methods=["GET"])
@MarshalWith(AllDataResponseSchema)
@require_user
def get_all_data(user: User) -> FluxData:
    user_dict = user.to_dict()
    user_dict["identities"] = user.identities.to_frontend_format()
    return success_response(payload=user_dict)


@pd_views.route("/identities", methods=["GET"])
@MarshalWith(IdentitiesResponseSchema)
@require_user
def get_identities(user) -> FluxData:
    return success_response(payload={"identities": user.identities.to_frontend_format()})


@pd_views.route("/user", methods=["GET"])
@MarshalWith(PersonalDataResponseSchema)
@require_user
def get_user(user: User) -> FluxData:
    return success_response(payload=user.to_dict())


@pd_views.route("/user", methods=["POST"])
@UnmarshalWith(PersonalDataRequestSchema)
@MarshalWith(PersonalDataResponseSchema)
@require_user
def update_personal_data(
    user: User, given_name: str, surname: str, language: str, chosen_given_name: Optional[str] = None
) -> FluxData:
    personal_data_user = PersonalDataUser.from_user(user, current_app.private_userdb)
    current_app.logger.debug(f"Trying to save user {user}")

    # disallow change of first name, surname if the user is verified
    if not user.identities.is_verified:
        personal_data_user.given_name = given_name
        personal_data_user.surname = surname

    # set chosen given name to either given name or a subset of given name if supplied
    # also allow to set chosen given name to None
    if (
        chosen_given_name is not None
        and is_valid_chosen_given_name(personal_data_user.given_name, chosen_given_name) is False
    ):
        return error_response(message=PDataMsg.chosen_given_name_invalid)

    # mypy borked?
    # error: Incompatible types in assignment (expression has type "str | None", variable has type "str")
    personal_data_user.chosen_given_name = chosen_given_name
    personal_data_user.language = language

    try:
        save_and_sync_user(personal_data_user)
    except UserOutOfSync:
        return error_response(message=CommonMsg.out_of_sync)
    current_app.stats.count(name="personal_data_saved", value=1)
    current_app.logger.info(f"Saved personal data for user {personal_data_user}")

    personal_data = personal_data_user.to_dict()
    return success_response(payload=personal_data, message=PDataMsg.save_success)


@pd_views.route("/settings", methods=["GET"])
@MarshalWith(UserSettingsResponseSchema)
@require_user
def get_user_settings(user: User) -> FluxData:
    payload = user.settings.model_dump()
    return success_response(payload=payload)


@pd_views.route("/settings", methods=["POST"])
@UnmarshalWith(UserSettingsRequestSchema)
@MarshalWith(UserSettingsResponseSchema)
@require_user
def set_user_settings(user: User, force_mfa: bool) -> FluxData:
    personal_data_user = PersonalDataUser.from_user(user, current_app.private_userdb)
    personal_data_user.settings.force_mfa = force_mfa
    current_app.logger.debug(f"Trying to save user settings {personal_data_user.settings}")

    try:
        save_and_sync_user(personal_data_user)
    except UserOutOfSync:
        return error_response(message=CommonMsg.out_of_sync)
    current_app.stats.count(name="user_settings_saved", value=1)

    current_app.logger.info("Saved user settings")
    return get_user_settings()
