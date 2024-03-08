from typing import Optional

from flask import Blueprint

from eduid.userdb import User
from eduid.userdb.exceptions import UserOutOfSync
from eduid.userdb.personal_data import PersonalDataUser
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.personal_data.app import current_pdata_app as current_app
from eduid.webapp.personal_data.helpers import PDataMsg
from eduid.webapp.personal_data.schemas import (
    AllDataResponseSchema,
    IdentitiesResponseSchema,
    PersonalDataRequestSchema,
    PersonalDataResponseSchema,
)

pd_views = Blueprint("personal_data", __name__, url_prefix="")


@pd_views.route("/all-user-data", methods=["GET"])
@MarshalWith(AllDataResponseSchema)
@require_user
def get_all_data(user: User) -> FluxData:
    user_dict = user.to_dict()
    user_dict["identities"] = user.identities.to_frontend_format()
    # TODO: remove nins after frontend stops using it
    user_dict["nins"] = []
    if user.identities.nin is not None:
        user_dict["nins"].append(user.identities.nin.to_old_nin())
    return success_response(payload=user_dict)


@pd_views.route("/user", methods=["GET"])
@MarshalWith(PersonalDataResponseSchema)
@require_user
def get_user(user: User) -> FluxData:
    return success_response(payload=user.to_dict())


@pd_views.route("/user", methods=["POST"])
@UnmarshalWith(PersonalDataRequestSchema)
@MarshalWith(PersonalDataResponseSchema)
@require_user
def post_user(user: User, given_name: str, surname: str, language: str, display_name: Optional[str] = None) -> FluxData:
    # TODO: Remove display_name when frontend stops sending it
    personal_data_user = PersonalDataUser.from_user(user, current_app.private_userdb)
    current_app.logger.debug(f"Trying to save user {user}")

    # disallow change of first name, surname and display name if the user is verified
    if not user.identities.is_verified:
        personal_data_user.given_name = given_name
        personal_data_user.surname = surname
        personal_data_user.display_name = f"{given_name} {surname}"
    personal_data_user.language = language
    try:
        save_and_sync_user(personal_data_user)
    except UserOutOfSync:
        return error_response(message=CommonMsg.out_of_sync)
    current_app.stats.count(name="personal_data_saved", value=1)
    current_app.logger.info(f"Saved personal data for user {personal_data_user}")

    personal_data = personal_data_user.to_dict()
    return success_response(payload=personal_data, message=PDataMsg.save_success)


@pd_views.route("/identities", methods=["GET"])
@MarshalWith(IdentitiesResponseSchema)
@require_user
def get_identities(user) -> FluxData:
    return success_response(payload={"identities": user.identities.to_frontend_format()})
