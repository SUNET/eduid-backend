from flask import Blueprint, abort, request
from marshmallow import ValidationError

from eduid.userdb.element import ElementKey
from eduid.userdb.exceptions import UserOutOfSync
from eduid.userdb.mail import MailAddress
from eduid.userdb.proofing import ProofingUser
from eduid.userdb.user import User
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.email.app import current_email_app as current_app
from eduid.webapp.email.helpers import EmailMsg
from eduid.webapp.email.schemas import (
    AddEmailSchema,
    ChangeEmailSchema,
    EmailListPayload,
    EmailResponseSchema,
    VerificationCodeSchema,
)
from eduid.webapp.email.verifications import send_verification_code, verify_mail_address

email_views = Blueprint("email", __name__, url_prefix="", template_folder="templates")


@email_views.route("/all", methods=["GET"])
@MarshalWith(EmailResponseSchema)
@require_user
def get_all_emails(user: User) -> FluxData:
    emails = {"emails": user.mail_addresses.to_list_of_dicts()}

    email_list = EmailListPayload().dump(emails)

    return success_response(payload=email_list, message=EmailMsg.get_success)


@email_views.route("/new", methods=["POST"])
@UnmarshalWith(AddEmailSchema)
@MarshalWith(EmailResponseSchema)
@require_user
def post_email(user: User, email: str, verified: bool, primary: bool) -> FluxData:
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    current_app.logger.debug(f"Trying to save unconfirmed email {repr(email)} for user {proofing_user}")

    new_mail = MailAddress(email=email, created_by="email", is_verified=False, is_primary=False)

    try:
        proofing_user.mail_addresses.add(new_mail)
    except ValidationError:
        # TODO: maybe check the validation error a bit more to see if duplicity was the problem
        return error_response(message=EmailMsg.dupe)

    try:
        save_and_sync_user(proofing_user)
    except UserOutOfSync:
        current_app.logger.debug(f"Couldn't save email {email} for user {proofing_user}, data out of sync")
        return error_response(message=CommonMsg.out_of_sync)
    current_app.logger.info(f"Saved unconfirmed email {repr(email)} for user {proofing_user}")
    current_app.stats.count(name="email_save_unconfirmed_email", value=1)

    sent = send_verification_code(email, proofing_user)
    emails = {"emails": proofing_user.mail_addresses.to_list_of_dicts()}
    email_list = EmailListPayload().dump(emails)

    if not sent:
        return success_response(payload=email_list, message=EmailMsg.added_and_throttled)

    current_app.stats.count(name="email_send_verification_code", value=1)

    return success_response(payload=email_list, message=EmailMsg.saved)


@email_views.route("/primary", methods=["POST"])
@UnmarshalWith(ChangeEmailSchema)
@MarshalWith(EmailResponseSchema)
@require_user
def post_primary(user: User, email: str) -> FluxData:
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    current_app.logger.debug(f"Trying to set email address {email!r} as primary for user {proofing_user}")

    mail = proofing_user.mail_addresses.find(email)
    if not mail:
        current_app.logger.debug(f"Couldnt save email {email!r} as primary for user {proofing_user}, data out of sync")
        return error_response(message=CommonMsg.out_of_sync)

    if not mail.is_verified:
        current_app.logger.debug(f"Couldnt save email {email!r} as primary for user {proofing_user}, email unconfirmed")
        return error_response(message=EmailMsg.unconfirmed_not_primary)

    proofing_user.mail_addresses.set_primary(mail.key)
    try:
        save_and_sync_user(proofing_user)
    except UserOutOfSync:
        current_app.logger.debug(
            f"Couldn't save email {repr(email)} as primary for user {proofing_user}, data out of sync"
        )
        return error_response(message=CommonMsg.out_of_sync)
    current_app.logger.info(f"Email address {repr(email)} made primary for user {proofing_user}")
    current_app.stats.count(name="email_set_primary", value=1)

    emails = {"emails": proofing_user.mail_addresses.to_list_of_dicts()}
    email_list = EmailListPayload().dump(emails)
    return success_response(payload=email_list, message=EmailMsg.success_primary)


@email_views.route("/verify", methods=["POST"])
@UnmarshalWith(VerificationCodeSchema)
@MarshalWith(EmailResponseSchema)
@require_user
def verify(user: User, code: str, email: str) -> FluxData:
    """
    Verify an email address with a code sent by email.
    """
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    current_app.logger.debug(f"Trying to save email address {email} as verified")

    db = current_app.proofing_statedb
    state = db.get_state_by_eppn_and_email(proofing_user.eppn, email)
    if not state:
        current_app.logger.info(f"Could not find proofing state for email {email}")
        return error_response(message=EmailMsg.unknown_email)
    if state.is_expired(int(current_app.conf.email_verification_timeout.total_seconds())):
        current_app.logger.info("Verification code is expired. Removing the state")
        current_app.logger.debug(f"Proofing state: {state}")
        current_app.proofing_statedb.remove_state(state)
        return error_response(message=EmailMsg.invalid_code)

    if code == state.verification.verification_code:
        try:
            verify_mail_address(state, proofing_user)
            current_app.logger.info("Email successfully verified")
            current_app.logger.debug(f"Email address: {email}")
            emails = {
                "emails": proofing_user.mail_addresses.to_list_of_dicts(),
            }
            email_list = EmailListPayload().dump(emails)
            return success_response(payload=email_list, message=EmailMsg.verify_success)
        except UserOutOfSync:
            current_app.logger.info("Could not confirm email, data out of sync")
            current_app.logger.debug(f"Mail address: {email}")
            return error_response(message=CommonMsg.out_of_sync)
    current_app.logger.info("Invalid verification code")
    current_app.logger.debug(f"Email address: {state.verification.email}")
    return error_response(message=EmailMsg.invalid_code)


@email_views.route("/remove", methods=["POST"])
@UnmarshalWith(ChangeEmailSchema)
@MarshalWith(EmailResponseSchema)
@require_user
def post_remove(user: User, email: ElementKey):
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    current_app.logger.debug(f"Trying to remove email address {email!r} from user {proofing_user}")

    # Do not let the user remove all mail addresses
    if proofing_user.mail_addresses.count == 1:
        current_app.logger.debug(f"Cannot remove the last address: {email}")
        return error_response(message=EmailMsg.cannot_remove_last)

    # Do not let the user remove all verified mail addresses
    verified_emails = proofing_user.mail_addresses.verified
    if len(verified_emails) == 1 and verified_emails[0].email == email:
        current_app.logger.debug(f"Cannot remove last verified address: {email}")
        return error_response(message=EmailMsg.cannot_remove_last_verified)

    proofing_user.mail_addresses.remove_handling_primary(email)

    try:
        save_and_sync_user(proofing_user)
    except UserOutOfSync:
        current_app.logger.debug(f"Could not remove email {email} for user, data out of sync")
        return error_response(message=CommonMsg.out_of_sync)

    current_app.logger.info(f"Email address {email} removed")
    current_app.stats.count(name="email_remove_success", value=1)

    _emails = {"emails": proofing_user.mail_addresses.to_list_of_dicts()}
    email_list = EmailListPayload().dump(_emails)
    return success_response(payload=email_list, message=EmailMsg.removal_success)


@email_views.route("/resend-code", methods=["POST"])
@UnmarshalWith(ChangeEmailSchema)
@MarshalWith(EmailResponseSchema)
@require_user
def resend_code(user: User, email: str) -> FluxData:
    current_app.logger.debug(f"Trying to send new verification code for email address {email} for user {user}")

    if not user.mail_addresses.find(email):
        current_app.logger.debug(f"Unknown email {email!r} in resend_code_action, user {user}")
        return error_response(message=CommonMsg.out_of_sync)

    sent = send_verification_code(email, user)
    if not sent:
        return error_response(message=EmailMsg.still_valid_code)

    current_app.logger.debug(f"New verification code sent to address {email} for user {user}")
    current_app.stats.count(name="email_resend_code", value=1)

    emails = {"emails": user.mail_addresses.to_list_of_dicts()}
    return success_response(payload=emails, message=EmailMsg.code_sent)


@email_views.route("/get-code", methods=["GET"])
@require_user
def get_code(user: User) -> str:
    """
    Backdoor to get the verification code in the staging or dev environments
    """
    try:
        if check_magic_cookie(current_app.conf):
            eppn = request.args.get("eppn")
            email = request.args.get("email")
            if not eppn or not email:
                # TODO: Return something better when the ENUMs have landed in master
                current_app.logger.error("Missing eppn or email")
                abort(400)
            state = current_app.proofing_statedb.get_state_by_eppn_and_email(eppn, email)
            if not state:
                current_app.logger.error(f"No state found for eppn {eppn} and email {email}")
                abort(400)
            return str(state.verification.verification_code)
    except Exception:
        current_app.logger.exception(f"{user} tried to use the backdoor to get the verification code for an email")

    abort(400)
