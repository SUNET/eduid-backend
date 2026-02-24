from typing import Any

from flask import Blueprint, render_template, request

from eduid.userdb import User
from eduid.userdb.exceptions import UserDoesNotExist, UserHasNotCompletedSignup
from eduid.userdb.signup import SignupUser
from eduid.userdb.support.models import SupportSignupUserFilter, SupportUserFilter
from eduid.userdb.support.user import SupportUser
from eduid.webapp.common.api.sanitation import sanitize_map
from eduid.webapp.support.app import current_support_app as current_app
from eduid.webapp.support.helpers import get_credentials_aux_data, require_login_with_mfa, require_support_personnel

support_views = Blueprint("support", __name__, url_prefix="", template_folder="templates")


@support_views.route("/", methods=["GET"])
def index() -> str:
    return render_template(
        "index.html",
    )


@support_views.route("/search-form", methods=["GET"])
@require_login_with_mfa
@require_support_personnel
def search_form(support_user: User) -> str:
    return render_template(
        "search_form.html", support_user=support_user, logout_url=current_app.conf.authn_service_url_logout
    )


@support_views.route("/search", methods=["POST"])
@require_login_with_mfa
@require_support_personnel
def search(support_user: User) -> str:
    data = sanitize_map(request.form)
    search_query = data.get("query")
    lookup_users: list[SupportUser | SignupUser] = []
    try:
        if search_query:
            lookup_users.extend(current_app.support_user_db.search_users(search_query))
    except UserHasNotCompletedSignup:
        # Old bug where incomplete signup users where written to central db
        pass
    users: list[dict[str, Any]] = list()

    if search_query and len(lookup_users) == 0:
        # If no users where found in the central database look in signup database
        lookup_users.extend(current_app.support_signup_db.get_users_by_mail(search_query, include_unconfirmed=True))
        if len(lookup_users) == 0:
            _user = current_app.support_signup_db.get_user_by_pending_mail_address(search_query)
            if _user:
                lookup_users.append(_user)
        if len(lookup_users) == 0:
            current_app.logger.warning(
                f"Support personnel {support_user.eppn} searched for {search_query!r} with no match found"
            )
            return render_template(
                "users.html",
                logout_url=current_app.conf.authn_service_url_logout,
                error=f"No users matched the search query: {search_query}",
            )

    current_app.logger.info(f"Support personnel {support_user.eppn} searched for {search_query!r}")
    for user in lookup_users:
        user_data: dict[str, Any] = dict()
        user_dict = user.to_dict()
        # Extend credentials with last used timestamp
        user_dict["passwords"] = get_credentials_aux_data(user)
        # Filter out unwanted data from user object
        user_data["user"] = SupportUserFilter(user_dict)
        user_data["signup_user"] = None
        try:
            signup_user = current_app.support_signup_db.get_user_by_id(user_id=user.user_id)
            if signup_user:
                user_data["signup_user"] = SupportSignupUserFilter(signup_user.to_dict())
        except (UserDoesNotExist, TypeError):
            # The user is in an old format
            pass

        # Aux data
        user_data["authn"] = current_app.support_authn_db.get_authn_info(user_id=user.user_id)
        user_data["proofing_log"] = current_app.support_proofing_log_db.get_entries(eppn=user.eppn)
        user_data["letter_proofing"] = current_app.support_letter_proofing_db.get_proofing_state(eppn=user.eppn)
        user_data["email_proofings"] = current_app.support_email_proofing_db.get_proofing_states(eppn=user.eppn)
        users.append(user_data)

    return render_template(
        "users.html",
        logout_url=current_app.conf.authn_service_url_logout,
        users=users,
        search_query=search_query,
    )
