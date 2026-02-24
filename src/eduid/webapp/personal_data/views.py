from flask import Blueprint

from eduid.common.config.base import FrontendAction
from eduid.userdb import User
from eduid.userdb.exceptions import UserOutOfSync
from eduid.userdb.personal_data import PersonalDataUser
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.common.authn.utils import check_reauthn
from eduid.webapp.personal_data.app import current_pdata_app as current_app
from eduid.webapp.personal_data.helpers import PDataMsg, is_valid_chosen_given_name
from eduid.webapp.personal_data.schemas import (
    AllDataResponseSchema,
    UserLanguageRequestSchema,
    UserLanguageResponseSchema,
    UserNameRequestSchema,
    UserNameResponseSchema,
    UserPreferencesRequestSchema,
    UserPreferencesResponseSchema,
)

pd_views = Blueprint("personal_data", __name__, url_prefix="")


@pd_views.route("/all-user-data", methods=["GET"])
@MarshalWith(AllDataResponseSchema)
@require_user
def get_all_data(user: User) -> FluxData:
    user_dict = user.to_dict()
    user_dict["identities"] = user.identities.to_frontend_format()
    return success_response(payload=user_dict)


@pd_views.route("/user/name", methods=["POST"])
@UnmarshalWith(UserNameRequestSchema)
@MarshalWith(UserNameResponseSchema)
@require_user
def update_user_name(user: User, given_name: str, surname: str, chosen_given_name: str | None = None) -> FluxData:
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

    try:
        save_and_sync_user(personal_data_user)
    except UserOutOfSync:
        return error_response(message=CommonMsg.out_of_sync)
    current_app.stats.count(name="user_name_saved", value=1)
    current_app.logger.info(f"Saved personal data for user {personal_data_user}")

    personal_data = personal_data_user.to_dict()
    return success_response(payload=personal_data, message=PDataMsg.save_success)


@pd_views.route("/user/language", methods=["POST"])
@UnmarshalWith(UserLanguageRequestSchema)
@MarshalWith(UserLanguageResponseSchema)
@require_user
def update_user_language(user: User, language: str) -> FluxData:
    personal_data_user = PersonalDataUser.from_user(user, current_app.private_userdb)
    current_app.logger.debug(f"Trying to save user {user}")

    personal_data_user.language = language

    try:
        save_and_sync_user(personal_data_user)
    except UserOutOfSync:
        return error_response(message=CommonMsg.out_of_sync)
    current_app.stats.count(name="user_language_saved", value=1)
    current_app.logger.info(f"Saved personal data for user {personal_data_user}")

    personal_data = personal_data_user.to_dict()
    return success_response(payload=personal_data, message=PDataMsg.save_success)


@pd_views.route("/preferences", methods=["POST"])
@UnmarshalWith(UserPreferencesRequestSchema)
@MarshalWith(UserPreferencesResponseSchema)
@require_user
def set_user_preferences(user: User, always_use_security_key: bool) -> FluxData:
    # When we get more user preferences we should probably split them into different groups
    # and have a separate endpoint for each group and FrontendAction.
    frontend_action = FrontendAction.CHANGE_SECURITY_PREFERENCES_AUTHN

    _need_reauthn = check_reauthn(frontend_action=frontend_action, user=user)
    if _need_reauthn:
        return _need_reauthn

    personal_data_user = PersonalDataUser.from_user(user, current_app.private_userdb)
    personal_data_user.preferences.always_use_security_key = always_use_security_key
    current_app.logger.debug(f"Trying to save user preferences {personal_data_user.preferences}")

    try:
        save_and_sync_user(personal_data_user)
    except UserOutOfSync:
        return error_response(message=CommonMsg.out_of_sync)
    current_app.stats.count(name="user_preferences_saved", value=1)

    current_app.logger.info("Saved user preferences")
    payload = personal_data_user.preferences.model_dump()
    return success_response(payload=payload)
