from flask import Blueprint

from eduid.common.config.base import FrontendAction
from eduid.common.misc.timeutil import utc_now
from eduid.common.rpc.exceptions import AmTaskFailed
from eduid.userdb import User
from eduid.userdb.exceptions import UserOutOfSync
from eduid.userdb.identity import IdentityType
from eduid.userdb.proofing import NinProofingElement
from eduid.userdb.proofing.state import NinProofingState
from eduid.userdb.security import SecurityUser
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.helpers import add_nin_to_user
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.csrf import EmptyRequest
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.common.authn.utils import get_authn_for_action
from eduid.webapp.common.authn.vccs import revoke_all_credentials
from eduid.webapp.common.session import session
from eduid.webapp.security.app import current_security_app as current_app
from eduid.webapp.security.helpers import (
    SecurityMsg,
    check_reauthn,
    compile_credential_list,
    remove_identity_from_user,
    remove_nin_from_user,
    send_termination_mail,
    update_user_official_name,
)
from eduid.webapp.security.schemas import (
    AccountTerminatedSchema,
    IdentitiesResponseSchema,
    IdentityRequestSchema,
    NINRequestSchema,
    SecurityResponseSchema,
    UserUpdateResponseSchema,
)

security_views = Blueprint("security", __name__, url_prefix="", template_folder="templates")


@security_views.route("/credentials", methods=["GET"])
@MarshalWith(SecurityResponseSchema)
@require_user
def get_credentials(user: User):
    """
    View to get credentials for the logged user.
    """
    current_app.logger.debug(f"Trying to get the credentials for user {user}")

    credentials = {"credentials": compile_credential_list(user)}

    return credentials


@security_views.route("/terminate-account", methods=["POST"])
@UnmarshalWith(EmptyRequest)
@MarshalWith(AccountTerminatedSchema)
@require_user
def terminate_account(user: User):
    """
    The account termination action,
    removes all credentials for the terminated account
    from the VCCS service,
    flags the account as terminated,
    sends an email to the address in the terminated account,
    and logs out the session.
    """
    frontend_action = FrontendAction.TERMINATE_ACCOUNT_AUTHN

    _need_reauthn = check_reauthn(frontend_action=frontend_action, user=user)
    if _need_reauthn:
        return _need_reauthn

    authn, _ = get_authn_for_action(config=current_app.conf, frontend_action=frontend_action)
    assert authn is not None  # please mypy (if authn was None we would have returned with _need_reauthn above)
    current_app.logger.debug(f"terminate_account called with authn {authn}")

    security_user = SecurityUser.from_user(user, current_app.private_userdb)

    # revoke all user passwords
    revoke_all_credentials(security_user, vccs_url=current_app.conf.vccs_url)
    # Skip removing old passwords from the user at this point as a password reset will do that anyway.
    # This fixes the problem with loading users for a password reset as users without passwords triggers
    # the UserHasNotCompletedSignup check in eduid-userdb.
    # TODO: Needs a decision on how to handle unusable user passwords
    # for p in security_user.credentials.filter(Password).to_list():
    #    security_user.passwords.remove(p.key)

    # flag account as terminated
    security_user.terminated = utc_now()
    try:
        save_and_sync_user(security_user)
    except UserOutOfSync:
        return error_response(message=CommonMsg.out_of_sync)

    current_app.stats.count(name="security_account_terminated", value=1)
    current_app.logger.info("Terminated user account")

    # email the user
    send_termination_mail(security_user)

    # log out the user
    authn.consumed = True
    current_app.logger.debug(f"Logging out (terminated) user {user}")
    return success_response(
        payload={"location": f"{current_app.conf.logout_endpoint}?next={current_app.conf.termination_redirect_url}"}
    )


@security_views.route("/add-nin", methods=["POST"])
@UnmarshalWith(NINRequestSchema)
@MarshalWith(IdentitiesResponseSchema)
@require_user
def add_nin(user: User, nin: str) -> FluxData:
    current_app.logger.info("Adding NIN to user")
    current_app.logger.debug(f"NIN: {nin}")

    if user.identities.nin is not None:
        current_app.logger.info("NIN already added.")
        return error_response(message=SecurityMsg.already_exists)

    nin_element = NinProofingElement(number=nin, created_by="security", is_verified=False)
    proofing_state = NinProofingState(id=None, eppn=user.eppn, nin=nin_element, modified_ts=None)

    try:
        security_user: SecurityUser = add_nin_to_user(user, proofing_state, user_type=SecurityUser)
    except AmTaskFailed:
        current_app.logger.exception("Adding nin to user failed")
        current_app.logger.debug(f"NIN: {nin}")
        return error_response(message=CommonMsg.temp_problem)

    return success_response(
        payload=dict(identities=security_user.identities.to_frontend_format()),
        message=SecurityMsg.add_success,
    )


@security_views.route("/remove-nin", methods=["POST"])
@UnmarshalWith(NINRequestSchema)
@MarshalWith(IdentitiesResponseSchema)
@require_user
def remove_nin(user: User, nin: str) -> FluxData:
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    current_app.logger.info("Removing NIN from user")
    current_app.logger.debug(f"NIN: {nin}")

    if user.identities.nin is not None:
        if user.identities.nin.number != nin:
            return success_response(
                payload=dict(identities=security_user.identities.to_frontend_format()), message=SecurityMsg.rm_success
            )

        if user.identities.nin.is_verified:
            current_app.logger.info("NIN verified. Will not remove it.")
            return error_response(message=SecurityMsg.rm_verified)

        try:
            remove_nin_from_user(security_user, user.identities.nin)
        except AmTaskFailed:
            current_app.logger.exception("Removing nin from user failed")
            current_app.logger.debug(f"NIN: {nin}")
            return error_response(message=CommonMsg.temp_problem)

    return success_response(
        payload=dict(identities=security_user.identities.to_frontend_format()),
        message=SecurityMsg.rm_success,
    )


@security_views.route("/remove-identity", methods=["POST"])
@UnmarshalWith(IdentityRequestSchema)
@MarshalWith(IdentitiesResponseSchema)
@require_user
def remove_identities(user: User, identity_type: str) -> FluxData:
    """
    Remove all verified identities from the user to let the user verify them again.
    This will not remove any locked identities.
    """

    frontend_action = FrontendAction.REMOVE_IDENTITY

    _need_reauthn = check_reauthn(frontend_action=frontend_action, user=user)
    if _need_reauthn:
        return _need_reauthn

    authn, _ = get_authn_for_action(config=current_app.conf, frontend_action=frontend_action)
    assert authn is not None  # please mypy (if authn was None we would have returned with _need_reauthn above)

    try:
        _type = IdentityType(identity_type)
    except ValueError:
        current_app.logger.error(f"Invalid identity type: {identity_type}")
        return error_response(message=SecurityMsg.wrong_identity_type)

    security_user = SecurityUser.from_user(user, current_app.private_userdb)

    current_app.logger.info(f"Removing _{type} identity from user")
    current_app.logger.debug(f"identities BEFORE: {security_user.identities}")

    try:
        remove_identity_from_user(security_user, _type)
    except AmTaskFailed:
        current_app.logger.exception(f"Removing identity of type {_type} from user failed")
        return error_response(message=CommonMsg.temp_problem)

    current_app.logger.debug(f"identities AFTER: {security_user.identities}")
    current_app.stats.count(name=f"remove_{_type}_identity")

    authn.consumed = True

    return success_response(
        payload=dict(identities=security_user.identities.to_frontend_format()),
        message=SecurityMsg.rm_success,
    )


@security_views.route("/refresh-official-user-data", methods=["POST"])
@UnmarshalWith(EmptyRequest)
@MarshalWith(UserUpdateResponseSchema)
@require_user
def refresh_user_data(user: User) -> FluxData:
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    if security_user.identities.nin is None or security_user.identities.nin.is_verified is False:
        return error_response(message=SecurityMsg.user_not_verified)

    current_app.stats.count(name="refresh_user_data_called")
    # only allow a user to request another update after throttle_update_user_period
    if session.security.user_requested_update is not None:
        retry_at = session.security.user_requested_update + current_app.conf.throttle_update_user_period
        if utc_now() < retry_at:
            return error_response(message=SecurityMsg.user_update_throttled)
    session.security.user_requested_update = utc_now()

    # Lookup person data via Navet
    current_app.logger.info("Getting Navet data for user")
    current_app.logger.debug(f"NIN: {security_user.identities.nin.number}")
    navet_data = current_app.msg_relay.get_all_navet_data(security_user.identities.nin.number)
    current_app.logger.debug(f"Navet data: {navet_data}")

    if navet_data.person.name.given_name is None or navet_data.person.name.surname is None:
        current_app.logger.info("Navet data incomplete for user")
        current_app.logger.debug(
            f"_given_name: {navet_data.person.name.given_name}, _surname: {navet_data.person.name.surname}"
        )
        current_app.stats.count(name="refresh_user_data_navet_data_incomplete")
        return error_response(message=SecurityMsg.navet_data_incomplete)

    # Update user official names if they differ
    if not update_user_official_name(security_user, navet_data):
        return error_response(message=CommonMsg.temp_problem)

    return success_response(message=SecurityMsg.user_updated)
