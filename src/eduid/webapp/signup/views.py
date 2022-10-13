# -*- coding: utf-8 -*-
from re import findall
from uuid import uuid4

from flask import Blueprint, abort, request

from eduid.common.misc.timeutil import utc_now
from eduid.userdb import User
from eduid.userdb.exceptions import UserOutOfSync
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.exceptions import ProofingLogFailure
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.base import FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import EmptyRequest
from eduid.webapp.common.api.utils import get_short_hash, make_short_code
from eduid.webapp.common.authn.utils import generate_password
from eduid.webapp.common.session import session
from eduid.webapp.signup.app import current_signup_app as current_app
from eduid.webapp.signup.helpers import (
    EmailAlreadyVerifiedException,
    EmailStatus,
    InviteNotFound,
    SignupMsg,
    check_email_status,
    complete_and_update_invite,
    create_and_sync_user,
    is_email_verification_expired,
    remove_users_with_mail_address,
    send_signup_mail,
    verify_recaptcha,
)
from eduid.webapp.signup.schemas import (
    AcceptTouRequest,
    AccountCreatedResponse,
    CaptchaCompleteRequest,
    CaptchaResponse,
    CreateUserRequest,
    EmailSchema,
    InviteCodeRequest,
    InviteDataResponse,
    RegisterEmailSchema,
    SignupStatusResponse,
    VerifyEmailRequest,
)

signup_views = Blueprint("signup", __name__, url_prefix="", template_folder="templates")


@signup_views.route("/state", methods=["GET"])
@MarshalWith(SignupStatusResponse)
def get_state():
    """
    Get the current signup state.
    """
    # TODO: write tests for this
    current_app.logger.debug("Get signup state")
    return success_response(payload=session.signup.to_dict())


@signup_views.route("/register-email", methods=["POST"])
@UnmarshalWith(EmailSchema)
@MarshalWith(SignupStatusResponse)
def register_email(email: str):
    """
    Register a with new email address.
    """
    current_app.logger.info("Registering email")
    current_app.logger.debug(f"email address: {email}")

    if not session.signup.captcha.completed:
        # don't allow registration without captcha completion
        # this is so that a malicious user can't send a lot of emails or enumerate email addresses already registered
        return error_response(message=SignupMsg.captcha_not_completed)

    email_status = check_email_status(email)
    if email_status == EmailStatus.ADDRESS_USED:
        current_app.logger.info("Email address already used")
        return error_response(payload=session.signup.to_dict(), message=SignupMsg.email_used)
    if email_status == EmailStatus.THROTTLED:
        current_app.logger.info("Email sending throttled")
        return error_response(payload=session.signup.to_dict(), message=SignupMsg.email_throttled)
    if email_status == EmailStatus.NEW:
        current_app.logger.info("Starting new signup")
        session.signup.email.address = email
        session.signup.email.verification_code = make_short_code(digits=current_app.conf.email_verification_code_length)
        session.signup.email.sent_at = utc_now()
        session.signup.email.reference = str(uuid4())

    # send email to the user
    if email_status in [EmailStatus.NEW, EmailStatus.RESEND_CODE]:
        current_app.logger.info("Sending verification email")
        assert session.signup.email.address is not None  # please mypy
        assert session.signup.email.verification_code is not None  # please mypy
        assert session.signup.email.reference is not None  # please mypy
        send_signup_mail(
            email=session.signup.email.address,
            verification_code=session.signup.email.verification_code,
            reference=session.signup.email.reference,
        )
        current_app.stats.count(name="verification_email_sent")

    return success_response(payload=session.signup.to_dict())


@signup_views.route("/verify-email", methods=["POST"])
@UnmarshalWith(VerifyEmailRequest)
@MarshalWith(SignupStatusResponse)
def verify_email(verification_code: str):
    """
    Verify the email address.
    """
    current_app.logger.info("Verifying email")
    current_app.logger.debug(f"email address: {session.signup.email.address}")
    current_app.logger.debug(f"verification code: {verification_code}")

    # ignore verification attempts if there has been to many wrong attempts
    if session.signup.email.bad_attempts >= current_app.conf.email_verification_max_bad_attempts:
        current_app.logger.info("Too many wrong verification attempts")
        # let user complete captcha again and reset bad attempts
        session.signup.captcha.completed = False
        session.signup.email.bad_attempts = 0
        return error_response(message=SignupMsg.email_verification_too_many_tries)

    if not session.signup.captcha.completed:
        return error_response(message=SignupMsg.captcha_not_completed)

    if is_email_verification_expired(sent_ts=session.signup.email.sent_at):
        current_app.logger.info("Email verification expired")
        return error_response(message=SignupMsg.email_verification_expired)

    if verification_code and verification_code == session.signup.email.verification_code:
        session.signup.email.completed = True
    else:
        current_app.logger.info("Verification failed")
        session.signup.email.bad_attempts += 1
        return error_response(message=SignupMsg.email_verification_failed)

    return success_response(payload=session.signup.to_dict())


@signup_views.route("/accept-tou", methods=["POST"])
@UnmarshalWith(AcceptTouRequest)
@MarshalWith(SignupStatusResponse)
def accept_tou(tou_accepted: bool, tou_version: str):
    """
    Accept the Terms of Use.
    """
    current_app.logger.info("Accepting ToU")
    if not tou_accepted:
        current_app.logger.info("ToU not completed")
        return error_response(message=SignupMsg.tou_not_completed)
    if tou_version != current_app.conf.tou_version:
        current_app.logger.error(f"ToU version: Got {tou_version}, expected {current_app.conf.tou_version}")
        return error_response(message=SignupMsg.tou_wrong_version)

    current_app.logger.info("ToU completed")
    session.signup.tou.completed = True
    session.signup.tou.version = tou_version
    return success_response(payload=session.signup.to_dict())


@signup_views.route("/captcha", methods=["GET"])
# @UnmarshalWith()
@MarshalWith(CaptchaResponse)
def captcha_request() -> FluxData:
    # TODO: respond with either new captcha or recaptcha
    pass


@signup_views.route("/captcha", methods=["POST"])
@UnmarshalWith(CaptchaCompleteRequest)
@MarshalWith(SignupStatusResponse)
def captcha_response(recaptcha_response: str) -> FluxData:
    """
    Check for humanness even at level AL1.
    """
    current_app.logger.info("Checking captcha")

    captcha_verified = False

    # add a backdoor to bypass recaptcha checks for humanness,
    # to be used in testing environments for automated integration tests.
    if check_magic_cookie(current_app.conf):
        current_app.logger.info("Using BACKDOOR to verify reCaptcha during signup!")
        captcha_verified = True

    # common path with no backdoor
    if recaptcha_response and not captcha_verified:
        remote_ip = request.remote_addr
        if current_app.conf.recaptcha_public_key and current_app.conf.recaptcha_private_key:
            captcha_verified = verify_recaptcha(current_app.conf.recaptcha_private_key, recaptcha_response, remote_ip)
        else:
            current_app.logger.info("Missing configuration for reCaptcha!")

    if not captcha_verified:
        current_app.logger.info("Captcha failed")
        return error_response(message=SignupMsg.captcha_failed)

    current_app.logger.info("Captcha completed")
    session.signup.captcha.completed = True
    return success_response(payload=session.signup.to_dict())


@signup_views.route("/get-password", methods=["POST"])
@UnmarshalWith(EmptyRequest)
@MarshalWith(SignupStatusResponse)
def get_password() -> FluxData:
    current_app.logger.info("Password requested")
    if session.signup.credentials.password is None:
        session.signup.credentials.password = generate_password(length=current_app.conf.password_length)
    return success_response(payload=session.signup.to_dict())


@signup_views.route("/create-user", methods=["POST"])
@UnmarshalWith(CreateUserRequest)
@MarshalWith(SignupStatusResponse)
def create_user(use_password: bool, use_webauthn: bool) -> FluxData:
    current_app.logger.info("Creating user")

    if session.common.eppn or session.signup.user_created:
        # do not try to create a new user if the user already exists
        current_app.logger.error("User already created")
        current_app.logger.debug(f"eppn: {session.common.eppn}")
        current_app.logger.debug(f"user created: {session.signup.user_created}")
        return error_response(message=SignupMsg.user_already_exists)

    if not session.signup.captcha.completed:
        current_app.logger.error("Captcha not completed")
        return error_response(message=SignupMsg.captcha_not_completed)
    if not session.signup.email.completed:
        current_app.logger.error("Email not completed")
        return error_response(message=SignupMsg.email_verification_not_complete)
    if not session.signup.tou.completed:
        current_app.logger.error("ToU not completed")
        return error_response(message=SignupMsg.tou_not_completed)
    if use_password and not session.signup.credentials.password:
        current_app.logger.error("No password generated")
        return error_response(message=SignupMsg.password_not_generated)
    if use_webauthn and not session.signup.credentials.webauthn:
        current_app.logger.error("No webauthn registered")
        return error_response(message=SignupMsg.webauthn_not_registered)
    if not use_password and not use_webauthn:
        current_app.logger.error("Neither password nor webauthn selected")
        return error_response(message=SignupMsg.credential_not_added)

    assert session.signup.email.address is not None  # please mypy
    assert session.signup.tou.version is not None  # please mypy
    try:
        signup_user = create_and_sync_user(
            email=session.signup.email.address,
            password=session.signup.credentials.password,
            tou_version=session.signup.tou.version,
        )
    except EmailAlreadyVerifiedException:
        return error_response(message=SignupMsg.email_used)
    except ProofingLogFailure:
        return error_response(message=CommonMsg.temp_problem)
    except UserOutOfSync:
        return error_response(message=CommonMsg.out_of_sync)

    session.signup.user_created = True
    session.signup.credentials.completed = True
    session.common.eppn = signup_user.eppn
    # create payload before clearing password
    payload = session.signup.to_dict()
    # clear password from session
    session.signup.credentials.password = None
    return success_response(payload=payload)


@signup_views.route("/invite-data", methods=["POST"])
@UnmarshalWith(InviteCodeRequest)
@MarshalWith(InviteDataResponse)
def get_invite(invite_code: str):
    invite = current_app.invite_db.get_invite_by_invite_code(code=invite_code)
    if invite is None:
        current_app.logger.error("Invite not found")
        current_app.logger.debug(f"invite_code: {invite_code}")
        return error_response(message=SignupMsg.invite_not_found)

    invite_data = {
        "is_logged_in": session.common.is_logged_in,
        "invite_type": invite.invite_type.value,
        "inviter_name": invite.inviter_name,
        "email": invite.get_primary_mail_address(),
        "preferred_language": invite.preferred_language,
        "expires_at": invite.expires_at,
        "given_name": invite.given_name,
        "surname": invite.surname,
        "finish_url": invite.finish_url,
    }

    if session.common.is_logged_in:
        user = current_app.central_userdb.get_user_by_eppn(eppn=session.common.eppn)
        if user is None:
            current_app.logger.error("User not found but logged in?")
            current_app.logger.error(f"invite_code: {invite_code}")
            raise RuntimeError("User not found but logged in?")
        assert user.mail_addresses.primary is not None  # please mypy
        invite_data["user"] = {
            "given_name": user.given_name,
            "surname": user.surname,
            "email": user.mail_addresses.primary.email,
        }

    return invite_data


@signup_views.route("/accept-invite", methods=["POST"])
@UnmarshalWith(InviteCodeRequest)
@MarshalWith(SignupStatusResponse)
def accept_invite(invite_code: str) -> FluxData:
    invite = current_app.invite_db.get_invite_by_invite_code(code=invite_code)
    if invite is None:
        current_app.logger.error("Invite not found")
        current_app.logger.debug(f"invite_code: {invite_code}")
        return error_response(message=SignupMsg.invite_not_found)

    if invite.completed_ts is not None:
        current_app.logger.error("Invite already completed")
        current_app.logger.debug(f"invite_code: {invite_code}")
        return error_response(message=SignupMsg.invite_already_completed)

    if invite.get_primary_mail_address() is not None:
        session.signup.email.address = invite.get_primary_mail_address()

    if invite.send_email is True:
        # user reached the invite endpoint after receiving an email
        # we can now set the email as completed
        session.signup.email.completed = True
        session.signup.email.sent_at = invite.created_ts

    session.signup.invite.invite_code = invite.invite_code
    session.signup.invite.initiated_signup = True
    return success_response(payload=session.signup.to_dict())


@signup_views.route("/complete-invite", methods=["POST"])
@MarshalWith(SignupStatusResponse)
def complete_invite() -> FluxData:
    current_app.logger.info("Completing invite")

    if not session.common.eppn or session.signup.invite.initiated_signup is False:
        return success_response(payload=session.signup.to_dict())

    user = current_app.central_userdb.get_user_by_eppn(eppn=session.common.eppn)
    if user is None:
        return error_response(message=CommonMsg.temp_problem)

    assert session.signup.invite.invite_code is not None  # please mypy
    try:
        complete_and_update_invite(user=user, invite_code=session.signup.invite.invite_code)
    except InviteNotFound:
        current_app.logger.info("Invite not found")
        return error_response(message=SignupMsg.invite_not_found)
    except UserOutOfSync:
        return error_response(message=CommonMsg.out_of_sync)

    current_app.logger.info("Invite completed for new user")
    current_app.stats.count(name="invite_completed_new_user")
    return success_response(payload=session.signup.to_dict())


@signup_views.route("/complete-invite-existing-user", methods=["POST"])
@MarshalWith(SignupStatusResponse)
@require_user
def complete_invite_existing_user(user: User) -> FluxData:
    current_app.logger.info("Completing invite for existing user")

    if session.signup.invite.initiated_signup is False:
        return success_response(payload=session.signup.to_dict())

    assert session.signup.invite.invite_code is not None  # please mypy
    try:
        complete_and_update_invite(user=user, invite_code=session.signup.invite.invite_code)
    except InviteNotFound:
        return error_response(message=SignupMsg.invite_not_found)
    except UserOutOfSync:
        return error_response(message=CommonMsg.out_of_sync)

    current_app.logger.info("Invite completed for existing user")
    current_app.stats.count(name="invite_completed_existing_user")
    return success_response(payload=session.signup.to_dict())


# BACKDOOR for testing
@signup_views.route("/get-code", methods=["GET"])
def get_email_code():
    """
    Backdoor to get the email verification code in the staging or dev environments
    """
    try:
        if check_magic_cookie(current_app.conf):
            email = request.args.get("email")
            if not email:
                current_app.logger.error("Missing email")
                abort(400)
            if session.signup.email.address == email:
                return session.signup.email.verification_code
    except Exception:
        current_app.logger.exception("Someone tried to use the backdoor to get the email verification code for signup")

    abort(400)


# backwards compatibility
@signup_views.route("/trycaptcha", methods=["POST"])
@UnmarshalWith(RegisterEmailSchema)
@MarshalWith(AccountCreatedResponse)
def trycaptcha(email: str, recaptcha_response: str, tou_accepted: bool) -> FluxData:
    """
    Kantara requires a check for humanness even at level AL1.
    """
    if not tou_accepted:
        return error_response(message=SignupMsg.tou_not_accepted)
    session.signup.tou.completed = True
    session.signup.tou.version = current_app.conf.tou_version

    recaptcha_verified = False

    # add a backdoor to bypass recaptcha checks for humanness,
    # to be used in testing environments for automated integration tests.
    if check_magic_cookie(current_app.conf):
        current_app.logger.info("Using BACKDOOR to verify reCaptcha during signup!")
        recaptcha_verified = True

    # common path with no backdoor
    if not recaptcha_verified:
        remote_ip = request.remote_addr

        if current_app.conf.recaptcha_public_key and current_app.conf.recaptcha_private_key:
            recaptcha_verified = verify_recaptcha(current_app.conf.recaptcha_private_key, recaptcha_response, remote_ip)
        else:
            current_app.logger.info("Missing configuration for reCaptcha!")

    if recaptcha_verified:
        session.signup.captcha.completed = True

        # if an old signup is in progress, let the user continue it
        signup_user = current_app.private_userdb.get_user_by_pending_mail_address(email)
        if signup_user is not None:
            assert signup_user.pending_mail_address is not None  # please mypy
            current_app.logger.debug("Found user {} with pending email {} in signup db".format(signup_user, email))
            session.signup.email.address = signup_user.pending_mail_address.email
            session.signup.email.verification_code = signup_user.pending_mail_address.verification_code
            session.signup.email.sent_at = signup_user.pending_mail_address.modified_ts

        _next = check_email_status(email)
        current_app.logger.info(f"recaptcha verified, next is {_next}")

        if _next == EmailStatus.ADDRESS_USED:
            current_app.stats.count(name="address_used_error")
            return error_response(payload=dict(next=_next), message=SignupMsg.old_email_used)
        elif _next == EmailStatus.THROTTLED:
            current_app.logger.info("throttled error")
            return error_response(payload=dict(next=_next), message=SignupMsg.email_throttled)
        elif _next == EmailStatus.NEW:
            # Workaround for failed earlier sync of user to userdb: Remove any signup_user with this e-mail address.
            remove_users_with_mail_address(email)

            session.signup.email.address = email
            session.signup.email.verification_code = get_short_hash(
                entropy=current_app.conf.email_verification_code_length
            )
            session.signup.email.sent_at = utc_now()
            session.signup.email.reference = str(uuid4())

            send_signup_mail(
                email=session.signup.email.address,
                verification_code=session.signup.email.verification_code,
                reference=session.signup.email.reference,
                use_email_link=True,
            )
            return success_response(payload=dict(next="new"), message=SignupMsg.reg_new)

        elif _next == EmailStatus.RESEND_CODE:
            assert session.signup.email.address is not None  # please mypy
            assert session.signup.email.verification_code is not None  # please mypy
            assert session.signup.email.reference is not None  # please mypy
            send_signup_mail(
                email=session.signup.email.address,
                verification_code=session.signup.email.verification_code,
                reference=session.signup.email.reference,
                use_email_link=True,
            )
            current_app.stats.count(name="resend_code")
            # Show the same end screen for resending a mail and a new registration
            return success_response(payload=dict(next="new"), message=SignupMsg.reg_new)

    return error_response(message=SignupMsg.no_recaptcha)


@signup_views.route("/verify-link/<code>", methods=["GET"])
@MarshalWith(FluxStandardAction)
def verify_link(code: str) -> FluxData:

    # ignore verification attempts if there has been to many wrong attempts
    if session.signup.email.bad_attempts >= current_app.conf.email_verification_max_bad_attempts:
        current_app.logger.info("Too many wrong verification attempts")
        return error_response(message=SignupMsg.email_verification_too_many_tries)

    if (
        is_email_verification_expired(sent_ts=session.signup.email.sent_at)
        or session.signup.email.verification_code is None
        or session.signup.email.verification_code != code
    ):
        current_app.logger.info("Verification failed")
        session.signup.email.bad_attempts += 1
        return error_response(payload=dict(status="unknown-code"), message=SignupMsg.unknown_code)

    session.signup.email.completed = True
    session.signup.credentials.password = generate_password(length=current_app.conf.password_length)

    assert session.signup.email.address is not None  # please mypy
    assert session.signup.tou.version is not None  # please mypy
    try:
        signup_user = create_and_sync_user(
            email=session.signup.email.address,
            password=session.signup.credentials.password,
            tou_version=session.signup.tou.version,
        )

    except EmailAlreadyVerifiedException:
        return error_response(payload=dict(status="already-verified"), message=SignupMsg.already_verified)
    except ProofingLogFailure:
        return error_response(message=CommonMsg.temp_problem)
    except UserOutOfSync:
        return error_response(message=CommonMsg.out_of_sync)

    parts = findall(".{,4}", session.signup.credentials.password)
    password = " ".join(parts).rstrip()

    context = {
        "status": "verified",
        "password": password,
        "dashboard_url": current_app.conf.dashboard_url,
    }

    if signup_user.mail_addresses.primary:
        context["email"] = signup_user.mail_addresses.primary.email

    current_app.stats.count(name="signup_complete")
    current_app.logger.info(f"Signup process for new user {signup_user} complete")
    return success_response(payload=context)


# end backwards compatibility
