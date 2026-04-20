from typing import Any
from uuid import uuid4

from fido2.webauthn import AuthenticatorAttachment, PublicKeyCredentialUserEntity
from fido_mds.models.webauthn import AttestationFormat
from flask import Blueprint, abort, request

from eduid.common.misc.timeutil import utc_now
from eduid.common.utils import generate_password
from eduid.userdb import User
from eduid.userdb.credentials import Webauthn
from eduid.userdb.exceptions import UserOutOfSync
from eduid.webapp.common.api.captcha import CaptchaCompleteRequest, CaptchaResponse
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_not_logged_in, require_user
from eduid.webapp.common.api.exceptions import ProofingLogFailure
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.base import FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import EmptyRequest
from eduid.webapp.common.api.utils import make_short_code
from eduid.webapp.common.authn.webauthn import (
    AuthenticatorInformation,
    RegistrationError,
    get_webauthn_server,
    verify_webauthn_registration,
)
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import WebauthnCredential, WebauthnRegistration
from eduid.webapp.signup.app import current_signup_app as current_app
from eduid.webapp.signup.helpers import (
    EmailAlreadyVerifiedException,
    EmailStatus,
    InviteNotFound,
    SignupMsg,
    check_email_status,
    complete_and_update_invite,
    create_and_sync_user,
    get_eppn,
    is_email_verification_expired,
    is_valid_custom_password,
    send_signup_mail,
)
from eduid.webapp.signup.schemas import (
    AcceptTouRequest,
    CreateUserRequest,
    InviteCodeRequest,
    InviteDataResponse,
    NameAndEmailSchema,
    SignupStatusResponse,
    VerifyEmailRequest,
    WebauthnRegisterBeginRequest,
    WebauthnRegisterCompleteRequest,
)

signup_views = Blueprint("signup", __name__, url_prefix="", template_folder="templates")


@signup_views.route("/state", methods=["GET"])
@MarshalWith(SignupStatusResponse)
def get_state() -> FluxData:
    """
    Get the current signup state.
    """
    # TODO: write tests for this
    current_app.logger.debug("Get signup state")
    return success_response(payload={"state": session.signup.to_dict()})


@signup_views.route("/register-email", methods=["POST"])
@UnmarshalWith(NameAndEmailSchema)
@MarshalWith(SignupStatusResponse)
@require_not_logged_in
def register_email(given_name: str, surname: str, email: str) -> FluxData:
    """
    Register a with new email address.
    """
    current_app.logger.info("Registering email")
    current_app.logger.debug(f"email address: {email}")

    if not session.signup.captcha.completed:
        # don't allow registration without captcha completion
        # this is so that a malicious user can't send a lot of emails or enumerate email addresses already registered
        current_app.logger.info("Captcha not completed")
        return error_response(message=SignupMsg.captcha_not_completed)

    if session.signup.email.completed:
        current_app.logger.info("Email already verified")
        return success_response(payload={"state": session.signup.to_dict()})

    email_status = check_email_status(email)
    if email_status == EmailStatus.ADDRESS_USED:
        current_app.logger.info("Email address already used")
        current_app.stats.count(name="address_used_error")
        return error_response(message=SignupMsg.email_used)
    elif email_status == EmailStatus.THROTTLED:
        current_app.logger.info("Email sending throttled")
        return error_response(message=SignupMsg.email_throttled)
    elif email_status == EmailStatus.RESEND_CODE:
        current_app.stats.count(name="resend_code")
    elif email_status == EmailStatus.NEW:
        current_app.logger.info("Starting new signup")
        # make sure the session is clean
        session.signup.email.clear()
        session.signup.name.clear()
        session.signup.name.given_name = given_name
        session.signup.name.surname = surname
        session.signup.email.address = email
        session.signup.email.verification_code = make_short_code(digits=current_app.conf.email_verification_code_length)
        session.signup.email.sent_at = utc_now()
        session.signup.email.reference = str(uuid4())
    else:
        current_app.logger.error(f"Unknown email status: {email_status}")
        return error_response(message=CommonMsg.temp_problem)

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

    return success_response(payload={"state": session.signup.to_dict()})


@signup_views.route("/verify-email", methods=["POST"])
@UnmarshalWith(VerifyEmailRequest)
@MarshalWith(SignupStatusResponse)
@require_not_logged_in
def verify_email(verification_code: str) -> FluxData:
    """
    Verify the email address.
    """
    current_app.logger.info("Verifying email")
    current_app.logger.debug(f"email address: {session.signup.email.address}")
    current_app.logger.debug(f"verification code: {verification_code}")

    if not session.signup.captcha.completed:
        current_app.logger.info("Captcha not completed")
        return error_response(message=SignupMsg.captcha_not_completed)

    if session.signup.email.completed:
        current_app.logger.info("Email already verified")
        return success_response(payload={"state": session.signup.to_dict()})

    if is_email_verification_expired(sent_ts=session.signup.email.sent_at):
        current_app.logger.info("Email verification expired")
        return error_response(message=SignupMsg.email_verification_expired)

    if verification_code and verification_code == session.signup.email.verification_code:
        session.signup.email.completed = True
    else:
        current_app.logger.info("Verification failed")
        session.signup.email.bad_attempts += 1

        if session.signup.email.bad_attempts >= current_app.conf.email_verification_max_bad_attempts:
            current_app.logger.info("Too many incorrect verification attempts")
            # let user complete captcha again and reset bad attempts
            session.signup.captcha.completed = False
            state = session.signup.to_dict()
            # reset bad attempts after we copied the state as frontend needs to know the number of bad attempts
            session.signup.email.bad_attempts = 0
            return error_response(payload={"state": state}, message=SignupMsg.email_verification_too_many_tries)

        return error_response(payload={"state": session.signup.to_dict()}, message=SignupMsg.email_verification_failed)

    return success_response(payload={"state": session.signup.to_dict()})


@signup_views.route("/accept-tou", methods=["POST"])
@UnmarshalWith(AcceptTouRequest)
@MarshalWith(SignupStatusResponse)
@require_not_logged_in
def accept_tou(tou_accepted: bool, tou_version: str) -> FluxData:
    """
    Accept the Terms of Use.
    """
    current_app.logger.info(f"Accepting ToU: {tou_accepted}, version: {tou_version}")

    if session.signup.tou.completed:
        current_app.logger.info("ToU already completed")
        return success_response(payload={"state": session.signup.to_dict()})

    if not tou_accepted:
        current_app.logger.info("ToU not completed")
        return error_response(message=SignupMsg.tou_not_completed)
    if tou_version != current_app.conf.tou_version:
        current_app.logger.error(f"ToU version: Got {tou_version}, expected {current_app.conf.tou_version}")
        return error_response(message=SignupMsg.tou_wrong_version)

    current_app.logger.info("ToU completed")
    session.signup.tou.completed = True
    session.signup.tou.version = tou_version
    return success_response(payload={"state": session.signup.to_dict()})


@signup_views.route("/get-captcha", methods=["POST"])
@UnmarshalWith(EmptyRequest)
@MarshalWith(CaptchaResponse)
@require_not_logged_in
def captcha_request() -> FluxData:
    if session.signup.captcha.completed:
        return error_response(message=SignupMsg.captcha_already_completed)

    session.signup.captcha.internal_answer = make_short_code(digits=current_app.conf.captcha_code_length)
    session.signup.captcha.bad_attempts = 0
    captcha_payload = current_app.captcha.get_request_payload(answer=session.signup.captcha.internal_answer)
    return success_response(payload=captcha_payload)


@signup_views.route("/captcha", methods=["POST"])
@UnmarshalWith(CaptchaCompleteRequest)
@MarshalWith(SignupStatusResponse)
@require_not_logged_in
def captcha_response(internal_response: str | None = None) -> FluxData:
    """
    Check for humanness even at level AL1.
    """
    current_app.logger.info("Checking captcha")

    if session.signup.captcha.completed:
        current_app.logger.info("Captcha already completed")
        return error_response(message=SignupMsg.captcha_already_completed)

    captcha_verified = False

    if session.signup.captcha.bad_attempts >= current_app.conf.captcha_max_bad_attempts:
        current_app.logger.info("Too many incorrect captcha attempts")
        # bad attempts is reset when a new captcha is generated
        return error_response(message=SignupMsg.captcha_failed)

    # add a backdoor to bypass captcha checks for humanness,
    # to be used in testing environments for automated integration tests.
    if check_magic_cookie(current_app.conf):
        current_app.logger.info("Using BACKDOOR to verify captcha during signup!")
        captcha_verified = True
        if internal_response is not None and internal_response != current_app.conf.captcha_backdoor_code:
            # used for testing failed captcha attempts
            current_app.logger.info("Incorrect captcha backdoor code")
            captcha_verified = False

    # common path with no backdoor
    if internal_response and not captcha_verified:
        if session.signup.captcha.internal_answer is None:
            return error_response(message=SignupMsg.captcha_not_requested)
        captcha_verified = internal_response == session.signup.captcha.internal_answer

    if not captcha_verified:
        current_app.logger.info("Captcha failed")
        session.signup.captcha.bad_attempts += 1
        return error_response(message=SignupMsg.captcha_failed)

    current_app.logger.info("Captcha completed")
    session.signup.captcha.completed = True
    return success_response(payload={"state": session.signup.to_dict()})


@signup_views.route("/get-password", methods=["POST"])
@UnmarshalWith(EmptyRequest)
@MarshalWith(SignupStatusResponse)
@require_not_logged_in
def get_password() -> FluxData:
    current_app.logger.info("Password requested")
    if session.signup.credentials.generated_password is None:
        session.signup.credentials.generated_password = generate_password(length=current_app.conf.password_length)
        session.signup.credentials.completed = True
    return success_response(payload={"state": session.signup.to_dict()})


@signup_views.route("/webauthn/register/begin", methods=["POST"])
@UnmarshalWith(WebauthnRegisterBeginRequest)
@MarshalWith(FluxStandardAction)
@require_not_logged_in
def webauthn_register_begin(authenticator: str) -> FluxData:
    current_app.logger.info("WebAuthn registration begin")

    if not session.signup.captcha.completed:
        return error_response(message=SignupMsg.captcha_not_completed)
    if not session.signup.email.completed:
        return error_response(message=SignupMsg.email_verification_not_complete)
    if not session.signup.tou.completed:
        return error_response(message=SignupMsg.tou_not_completed)

    try:
        _auth_enum = AuthenticatorAttachment(authenticator)
    except ValueError:
        return error_response(message=SignupMsg.webauthn_registration_failed)

    eppn = get_eppn()

    server = get_webauthn_server(
        rp_id=current_app.conf.fido2_rp_id,
        rp_name=current_app.conf.fido2_rp_name,
        attestation=current_app.conf.webauthn_attestation,
    )

    if not session.signup.name.given_name or not session.signup.name.surname:
        return error_response(message=SignupMsg.name_not_set)
    user_entity = PublicKeyCredentialUserEntity(
        id=bytes(eppn, "utf-8"),
        name=eppn,
        display_name=f"{session.signup.name.given_name} {session.signup.name.surname}",
    )
    registration_data, state = server.register_begin(
        user=user_entity,
        credentials=[],
        user_verification=current_app.conf.webauthn_user_verification,
        resident_key_requirement=current_app.conf.webauthn_resident_key_requirement,
        authenticator_attachment=_auth_enum,
        extensions={"credProps": True},
    )
    session.signup.credentials.webauthn_registration = WebauthnRegistration(
        webauthn_state=state, authenticator=_auth_enum
    )

    current_app.logger.info("WebAuthn registration begun")
    current_app.stats.count(name="webauthn_register_begin")

    return success_response(
        payload={"csrf_token": session.new_csrf_token(), "registration_data": dict(registration_data)}
    )


@signup_views.route("/webauthn/register/complete", methods=["POST"])
@UnmarshalWith(WebauthnRegisterCompleteRequest)
@MarshalWith(SignupStatusResponse)
@require_not_logged_in
def webauthn_register_complete(
    response: dict[str, Any], description: str, client_extension_results: dict[str, Any] | None = None
) -> FluxData:
    current_app.logger.info("WebAuthn registration complete")

    if not session.signup.credentials.webauthn_registration:
        current_app.logger.info("Found no webauthn registration state in the session")
        return error_response(message=SignupMsg.webauthn_registration_failed)

    reg_state = session.signup.credentials.webauthn_registration
    session.signup.credentials.webauthn_registration = None

    try:
        result = verify_webauthn_registration(
            response=response,
            webauthn_state=reg_state.webauthn_state,
            authenticator=reg_state.authenticator,
            rp_id=current_app.conf.fido2_rp_id,
            rp_name=current_app.conf.fido2_rp_name,
            fido_mds=current_app.fido_mds,
            fido_metadata_log=current_app.fido_metadata_log,
            app_name=current_app.conf.app_name,
            is_backdoor=check_magic_cookie(current_app.conf),
            disallowed_status=current_app.conf.webauthn_disallowed_status,
            client_extension_results=client_extension_results,
        )
    except RegistrationError:
        return error_response(message=SignupMsg.webauthn_registration_failed)

    # Store completed credential in session for user creation
    session.signup.credentials.webauthn = WebauthnCredential(
        credential_data=result.credential_data,
        keyhandle=result.keyhandle,
        authenticator=result.authenticator,
        authenticator_id=str(result.authenticator_info.authenticator_id),
        mfa_approved=result.mfa_approved,
        attestation_format=result.authenticator_info.attestation_format,
        description=description,
        user_present=result.authenticator_info.user_present,
        user_verified=result.authenticator_info.user_verified,
        user_verification_methods=result.authenticator_info.user_verification_methods,
        key_protection=result.authenticator_info.key_protection,
    )
    session.signup.credentials.completed = True

    current_app.logger.info("WebAuthn registration completed")
    current_app.stats.count(name="webauthn_register_complete")
    if result.mfa_approved:
        current_app.stats.count(name="webauthn_mfa_approved")

    return success_response(payload={"state": session.signup.to_dict()})


@signup_views.route("/create-user", methods=["POST"])
@UnmarshalWith(CreateUserRequest)
@MarshalWith(SignupStatusResponse)
@require_not_logged_in
def create_user(use_suggested_password: bool, use_webauthn: bool, custom_password: str | None = None) -> FluxData:
    current_app.logger.info("Creating user")

    use_password = False
    if use_suggested_password or custom_password is not None:
        use_password = True

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
    if use_password and not session.signup.credentials.generated_password:
        current_app.logger.error("No generated_password generated")
        return error_response(message=SignupMsg.password_not_generated)
    if use_password and custom_password is not None:
        if not is_valid_custom_password(custom_password):
            current_app.logger.error("Weak custom password")
            return error_response(message=SignupMsg.weak_custom_password)
    if use_webauthn and not session.signup.credentials.webauthn:
        current_app.logger.error("No webauthn registered")
        return error_response(message=SignupMsg.webauthn_registration_failed)
    if not use_password and not use_webauthn:
        current_app.logger.error("Neither generated_password nor webauthn selected")
        return error_response(message=SignupMsg.credential_not_added)

    assert session.signup.name.given_name is not None  # please mypy
    assert session.signup.name.surname is not None  # please mypy
    assert session.signup.email.address is not None  # please mypy
    assert session.signup.tou.version is not None  # please mypy

    webauthn_credential = None
    webauthn_authenticator_info = None
    if use_webauthn:
        wn = session.signup.credentials.webauthn
        assert wn is not None  # checked above
        webauthn_credential = Webauthn(
            keyhandle=wn.keyhandle,
            credential_data=wn.credential_data,
            authenticator_id=wn.authenticator_id,
            authenticator=wn.authenticator,
            app_id=current_app.conf.fido2_rp_id,
            description=wn.description,
            created_by=current_app.conf.app_name,
            mfa_approved=wn.mfa_approved,
            webauthn_proofing_version=current_app.conf.webauthn_proofing_version,
            attestation_format=wn.attestation_format,
        )
        webauthn_authenticator_info = AuthenticatorInformation(
            authenticator_id=wn.authenticator_id or "",
            attestation_format=wn.attestation_format or AttestationFormat.NONE,
            user_present=wn.user_present,
            user_verified=wn.user_verified,
            user_verification_methods=wn.user_verification_methods,
            key_protection=wn.key_protection,
        )

    try:
        signup_user = create_and_sync_user(
            given_name=session.signup.name.given_name,
            surname=session.signup.name.surname,
            email=session.signup.email.address,
            generated_password=session.signup.credentials.generated_password,
            custom_password=custom_password,
            tou_version=session.signup.tou.version,
            webauthn=webauthn_credential,
            webauthn_authenticator_info=webauthn_authenticator_info,
        )
    except EmailAlreadyVerifiedException:
        return error_response(message=SignupMsg.email_used)
    except ProofingLogFailure:
        return error_response(message=CommonMsg.temp_problem)
    except UserOutOfSync:
        return error_response(message=CommonMsg.out_of_sync)

    session.signup.user_created = True
    session.signup.user_created_at = utc_now()
    session.signup.credentials.completed = True
    session.common.eppn = signup_user.eppn
    # create payload before clearing generated password
    state = session.signup.to_dict()
    if custom_password is not None:
        state["credentials"]["custom_password"] = True
        state["credentials"]["generated_password"] = None
        current_app.stats.count(name="custom_password")
    # clear passwords from session and namespace
    del custom_password
    session.signup.credentials.generated_password = None
    # clear signup session if the user is done
    if not session.signup.invite.initiated_signup:
        del session.signup
    current_app.stats.count(name="signup_complete")
    return success_response(payload={"state": state})


@signup_views.route("/invite-data", methods=["POST"])
@UnmarshalWith(InviteCodeRequest)
@MarshalWith(InviteDataResponse)
def get_invite(invite_code: str) -> FluxData:
    invite = current_app.invite_db.get_invite_by_invite_code(code=invite_code)
    if invite is None:
        current_app.logger.error("Invite not found")
        current_app.logger.debug(f"invite_code: {invite_code}")
        return error_response(message=SignupMsg.invite_not_found)

    invite_data: dict[str, Any] = {
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
        assert user.mail_addresses.primary is not None  # please mypy
        invite_data["user"] = {
            "given_name": user.given_name,
            "surname": user.surname,
            "email": user.mail_addresses.primary.email,
        }

    return success_response(payload=invite_data)


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

    if invite.given_name is not None:
        session.signup.name.given_name = invite.given_name

    if invite.surname is not None:
        session.signup.name.surname = invite.surname

    if invite.get_primary_mail_address() is not None:
        session.signup.email.address = invite.get_primary_mail_address()

    if invite.send_email is True:
        # user reached the invite endpoint after receiving an email
        # we can now set the email as completed
        session.signup.email.completed = True
        session.signup.email.sent_at = invite.created_ts

    session.signup.invite.invite_code = invite.invite_code
    session.signup.invite.initiated_signup = True
    return success_response(payload={"state": session.signup.to_dict()})


@signup_views.route("/complete-invite", methods=["POST"])
@MarshalWith(SignupStatusResponse)
def complete_invite() -> FluxData:
    current_app.logger.info("Completing invite")

    if not session.common.eppn or session.signup.invite.initiated_signup is False:
        return success_response(payload={"state": session.signup.to_dict()})

    user = current_app.central_userdb.get_user_by_eppn(eppn=session.common.eppn)

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
    state = session.signup.to_dict()
    del session.signup
    return success_response(payload={"state": state})


@signup_views.route("/complete-invite-existing-user", methods=["POST"])
@MarshalWith(SignupStatusResponse)
@require_user
def complete_invite_existing_user(user: User) -> FluxData:
    current_app.logger.info("Completing invite for existing user")

    if session.signup.invite.initiated_signup is False:
        return success_response(payload={"state": session.signup.to_dict()})

    assert session.signup.invite.invite_code is not None  # please mypy
    try:
        complete_and_update_invite(user=user, invite_code=session.signup.invite.invite_code)
    except InviteNotFound:
        return error_response(message=SignupMsg.invite_not_found)
    except UserOutOfSync:
        return error_response(message=CommonMsg.out_of_sync)

    current_app.logger.info("Invite completed for existing user")
    current_app.stats.count(name="invite_completed_existing_user")
    state = session.signup.to_dict()
    del session.signup
    return success_response(payload={"state": state})


# BACKDOOR for testing
@signup_views.route("/get-code", methods=["GET"])
def get_email_code() -> str:
    """
    Backdoor to get the email verification code in the staging or dev environments
    """
    try:
        if check_magic_cookie(current_app.conf):
            email = request.args.get("email")
            current_app.logger.debug(f"BACKDOOR: requesting code for email: {email}")
            if not email:
                current_app.logger.error("BACKDOOR: Missing email")
                abort(400)
            current_app.logger.debug(f"BACKDOOR: email in session: {session.signup.email.address}")
            if session.signup.email.address == email:
                code = session.signup.email.verification_code
                return code or ""
    except Exception:
        current_app.logger.exception("Someone tried to use the backdoor to get the email verification code for signup")

    abort(400)
