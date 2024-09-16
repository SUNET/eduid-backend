from collections.abc import Sequence
from typing import Optional

from bson import ObjectId
from flask import Blueprint

from eduid.common.config.base import EduidEnvironment
from eduid.userdb import ToUEvent
from eduid.userdb.actions.tou.user import ToUUser
from eduid.userdb.exceptions import UserOutOfSync
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.decorators import require_ticket, uses_sso_session
from eduid.webapp.idp.helpers import IdPMsg, lookup_user
from eduid.webapp.idp.login_context import LoginContext
from eduid.webapp.idp.schemas import TouRequestSchema, TouResponseSchema
from eduid.webapp.idp.sso_session import SSOSession

tou_views = Blueprint("tou", __name__, url_prefix="")


@tou_views.route("/tou", methods=["POST"])
@UnmarshalWith(TouRequestSchema)
@MarshalWith(TouResponseSchema)
@require_ticket
@uses_sso_session
def tou(
    ticket: LoginContext,
    sso_session: Optional[SSOSession],
    versions: Optional[Sequence[str]] = None,
    user_accepts: Optional[str] = None,
) -> FluxData:
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- Terms of Use ({ticket.request_ref}) ---")

    if not current_app.conf.login_bundle_url:
        return error_response(message=IdPMsg.not_available)

    if user_accepts:
        if user_accepts != current_app.conf.tou_version:
            return error_response(message=IdPMsg.tou_not_acceptable)

        if not sso_session:
            current_app.logger.error("TOU called without an SSO session")
            return error_response(message=IdPMsg.general_failure)

        user = lookup_user(sso_session.eppn)
        if not user:
            current_app.logger.error(f"User with eppn {sso_session.eppn} (from SSO session) not found")
            return error_response(message=IdPMsg.general_failure)

        current_app.logger.info(f"ToU version {user_accepts} accepted by user {user}")

        tou_user = ToUUser.from_user(user, current_app.tou_db)

        if current_app.conf.environment == EduidEnvironment.dev:
            # Filter out old events for the same version, to not get too much log spam with hundreds
            # of ToUEvent on users in development logs
            keys_with_version = [x.key for x in tou_user.tou.to_list() if x.version == user_accepts]
            for remove_key in keys_with_version[:-2]:
                # remove all but the last two of this version
                tou_user.tou.remove(remove_key)

        # TODO: change event_id to an UUID? ObjectId is only 'likely unique'
        tou_user.tou.add(ToUEvent(version=user_accepts, created_by="eduid_login", event_id=str(ObjectId())))

        try:
            res = save_and_sync_user(
                tou_user,
                private_userdb=current_app.tou_db,  # type: ignore[arg-type]
                app_name_override="eduid_tou",
            )
        except UserOutOfSync:
            current_app.logger.debug(f"Couldn't save ToU {user_accepts} for user {tou_user}, data out of sync")
            return error_response(message=CommonMsg.out_of_sync)

        if not res:
            current_app.logger.error("Failed saving/syncing user after accepting ToU")
            return error_response(message=IdPMsg.general_failure)

        return success_response(payload={"finished": True})

    if versions and current_app.conf.tou_version in versions:
        current_app.logger.debug(
            f"Available versions in frontend: {versions}, requesting {current_app.conf.tou_version}"
        )
        return success_response(payload={"finished": False, "version": current_app.conf.tou_version})

    current_app.logger.debug(
        f"Available versions in frontend: {versions}, current version {current_app.conf.tou_version} is not there"
    )
    return error_response(message=IdPMsg.tou_not_acceptable)
