"""
Here it is described the behaviour expected from a front side app that uses this
service. Just the main, success path will be described; to cover paths
taken due to error conditions, check the docstrings for each method, below.

We assume that this front side app is a login app that is already loaded in the
end user's browser, and which offers a "reset password" link side by side with
inputs for credentials.

When this "reset password" link is followed, the user will be presented a form,
with a text input for an email address and a "send" button. The user enters
(one of) her email(s) and submits the form, which results in a POST to the
init_reset_pw view (at /), with the email as only data.

The result of calling this init_reset_pw method will be the generation of a
password reset state in a db, keyed by a hash code, and the sending of an email
with a link that includes the mentioned hash code.

When the user follows the link in the email, the front app will load, it will
grab the code from document.location.href, and will use it to send a POST to
the config_reset_pw view located at /config/, with the code as only data. This
POST will return the same code, a suggested password, and an array of (masked)
verified phone numbers.

Now there are 2 possibilities.

The first happens when the user has no verified phone numbers. Then she will be
shown a form where she can choose the suggested password or enter a custom one,
submit it to the set_new_pw view at /new-password/, and have her password
reset as a result. In this case, with no extra security, all her verified phone
numbers and NINs will be unverified.

The second possibility is that the user had some phone number(s) verified. Then
she will be presented with a choice, to either use extra security, or not. If
she chooses not to use extra security, the workflow will continue as with the
first possibility.

If the user chooses extra security (clicking on a particular verified phone number),
an SMS with a new code will be sent to the chosen phone number, and the
user will be presented with the same form as in the first possibility,
supplemented with a text input for the SMS'ed code. In this case submitting the
form will also result in resetting her password, but without unverifying any of
her data.
"""

from flask import Blueprint, abort, request

from eduid.common.rpc.exceptions import MailTaskFailed, MsgTaskFailed
from eduid.userdb.exceptions import UserDoesNotExist, UserHasNotCompletedSignup
from eduid.userdb.reset_password import ResetPasswordEmailAndPhoneState
from eduid.webapp.common.api.captcha import CaptchaResponse, CaptchaCompleteRequest
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_not_logged_in
from eduid.webapp.common.api.exceptions import ThrottledException
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.csrf import EmptyResponse, EmptyRequest
from eduid.webapp.common.api.utils import get_zxcvbn_terms, hash_password, make_short_code
from eduid.webapp.common.authn import fido_tokens
from eduid.webapp.common.session import session
from eduid.webapp.reset_password.app import current_reset_password_app as current_app
from eduid.webapp.reset_password.helpers import (
    ResetPwMsg,
    StateException,
    email_state_to_response_payload,
    generate_suggested_password,
    get_context,
    get_extra_security_alternatives,
    mask_alternatives,
    reset_user_password,
    send_password_reset_mail,
    send_verify_phone_code,
    verify_email_address,
    verify_phone_number,
)
from eduid.webapp.reset_password.schemas import (
    NewPasswordSecurePhoneRequestSchema,
    NewPasswordSecureTokenRequestSchema,
    ResetPasswordEmailCodeRequestSchema,
    ResetPasswordEmailRequestSchema,
    ResetPasswordEmailResponseSchema,
    ResetPasswordExtraSecPhoneSchema,
    ResetPasswordResponseSchema,
    ResetPasswordVerifyEmailResponseSchema,
    ResetPasswordWithCodeSchema,
    ResetPasswordCaptchaResponseSchema,
)

SESSION_PREFIX = "eduid_webapp.reset_password.views"


reset_password_views = Blueprint("reset_password", __name__, url_prefix="/", template_folder="templates")


@reset_password_views.route("/", methods=["GET"])
@MarshalWith(EmptyResponse)
def init_reset_pw() -> FluxData:
    """
    Used only to get a csrf token, this can move to jsconfig if any other config is needed
    """
    return success_response()


@reset_password_views.route("/get-captcha", methods=["POST"])
@UnmarshalWith(EmptyRequest)
@MarshalWith(CaptchaResponse)
def captcha_request() -> FluxData:
    if session.reset_password.captcha.completed:
        return error_response(message=ResetPwMsg.captcha_already_completed)

    session.reset_password.captcha.internal_answer = make_short_code(digits=current_app.conf.captcha_code_length)
    session.reset_password.captcha.bad_attempts = 0
    captcha_payload = current_app.captcha.get_request_payload(answer=session.reset_password.captcha.internal_answer)
    return success_response(payload=captcha_payload)


@reset_password_views.route("/captcha", methods=["POST"])
@UnmarshalWith(CaptchaCompleteRequest)
@MarshalWith(ResetPasswordCaptchaResponseSchema)
def captcha_response(internal_response: str | None = None) -> FluxData:
    """
    Check for humanness even at level AL1.
    """
    current_app.logger.info("Checking captcha")

    if session.reset_password.captcha.completed:
        current_app.logger.info("Captcha already completed")
        return error_response(message=ResetPwMsg.captcha_already_completed)

    captcha_verified = False

    if session.reset_password.captcha.bad_attempts >= current_app.conf.captcha_max_bad_attempts:
        current_app.logger.info("Too many incorrect captcha attempts")
        # bad attempts is reset when a new captcha is generated
        return error_response(message=ResetPwMsg.captcha_failed)

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
        if session.reset_password.captcha.internal_answer is None:
            return error_response(message=ResetPwMsg.captcha_not_requested)
        captcha_verified = internal_response == session.reset_password.captcha.internal_answer

    if not captcha_verified:
        current_app.logger.info("Captcha failed")
        session.reset_password.captcha.bad_attempts += 1
        return error_response(message=ResetPwMsg.captcha_failed)

    current_app.logger.info("Captcha completed")
    session.reset_password.captcha.completed = True
    return success_response(message=ResetPwMsg.captcha_completed, payload={"captcha_completed": True})


@reset_password_views.route("/", methods=["POST"])
@UnmarshalWith(ResetPasswordEmailRequestSchema)
@MarshalWith(ResetPasswordEmailResponseSchema)
def start_reset_pw(email: str) -> FluxData:
    """
    View that receives an email address to initiate a reset password process.
    It returns a message informing of the result of the operation.

    As side effects, this view will:
    * Create a PasswordResetEmailState in the password_reset_state_db
      (holding the email address, the eppn of the user associated to the
      email address in the central userdb, and a freshly generated random hash
      as an identifier code for the created state);
    * Email the generated code to the received email address.

    The operation can fail due to:
    * The e-mail address is not found
    * There is some problem sending the email.
    """
    if not session.reset_password.captcha.completed:
        current_app.logger.error("Captcha not completed")
        return error_response(message=ResetPwMsg.captcha_not_completed)

    current_app.logger.info(f"Trying to send password reset email to {email}")
    try:
        state = send_password_reset_mail(email)
    except UserDoesNotExist:
        current_app.logger.error(f"No user with email {email} found")
        return error_response(message=ResetPwMsg.user_not_found)
    except ThrottledException as e:
        current_app.logger.error(f"Email resending throttled for {email}")
        return success_response(
            message=ResetPwMsg.email_send_throttled, payload=email_state_to_response_payload(e.state)
        )
    except UserHasNotCompletedSignup:
        # Old bug where incomplete signup users where written to the central db
        current_app.logger.exception(f"User with email {email} has to complete signup")
        return error_response(message=ResetPwMsg.invalid_user)
    except MailTaskFailed:
        current_app.logger.exception("Sending password reset email failed")
        return error_response(message=ResetPwMsg.email_send_failure)

    current_app.stats.count(name="email_sent", value=1)

    return success_response(message=ResetPwMsg.reset_pw_initialized, payload=email_state_to_response_payload(state))


@reset_password_views.route("/verify-email/", methods=["POST"])
@UnmarshalWith(ResetPasswordEmailCodeRequestSchema)
@MarshalWith(ResetPasswordVerifyEmailResponseSchema)
def verify_email(email_code: str) -> FluxData:
    """
    View that receives an emailed reset password code and returns the
    configuration needed for the reset password form.

    Preconditions required for the call to succeed:
    * A PasswordResetEmailState object in the password_reset_state_db
      keyed by the received code.

    The configuration returned (in case of success) will include:
    * The received code;
    * A newly generated suggested password;
    * In case the user corresponding to the email address has verified phone
      numbers, these will be sent (masked) to allow the user to use extra
      security. (If the user does not use extra security, any verified NIN or
      phone number will be unverified upon resetting the password).

    As side effects, this view will:
    * Create a MailAddressProofing element in the proofing_log;
    * Set the email_code.is_verified flag in the PasswordResetEmailState
      object;
    * Set a hash of the generated password in the session.

    This operation may fail due to:
    * The code does not correspond to a valid state in the db;
    * The code has expired;
    * No valid user corresponds to the eppn stored in the state.
    """
    current_app.logger.info(f"Configuring password reset form for {email_code}")
    try:
        context = get_context(email_code=email_code)
    except StateException as e:
        return error_response(message=e.msg)

    # User is at least partially authenticated, put the eppn in the shared session
    if session.common.eppn and session.common.eppn != context.user.eppn:
        # Do not allow eppn change in an existing session
        current_app.logger.warning(
            f"eppn in session {session.common.eppn} not same as in the state {context.user.eppn}. Removing session."
        )
        session.invalidate()
        return error_response(message=ResetPwMsg.invalid_session)
    session.common.eppn = context.user.eppn

    # TODO: Split this view to verify email address view and configuration view
    # Do not verify the email address again if it has been done already using this state
    if context.state.email_code.is_verified is False:
        verify_email_address(context.state)

    new_password = generate_suggested_password(password_length=current_app.conf.password_length)
    session.reset_password.generated_password_hash = hash_password(new_password)

    alternatives = get_extra_security_alternatives(context.user)
    context.state.extra_security = alternatives
    current_app.password_reset_state_db.save(context.state)
    current_app.stats.count(name="email_verified", value=1)
    return success_response(
        payload={
            "suggested_password": new_password,
            "email_code": context.state.email_code.code,
            "email_address": context.state.email_address,
            "extra_security": mask_alternatives(alternatives),
            "min_zxcvbn_score": current_app.conf.min_zxcvbn_score,
            "password_entropy": current_app.conf.password_entropy,
            "password_length": current_app.conf.password_length,
            "password_service_url": current_app.conf.password_service_url,
            "zxcvbn_terms": get_zxcvbn_terms(context.user),
        },
    )


@reset_password_views.route("/new-password/", methods=["POST"])
@UnmarshalWith(ResetPasswordWithCodeSchema)
@MarshalWith(ResetPasswordResponseSchema)
def set_new_pw_no_extra_security(email_code: str, password: str) -> FluxData:
    """
    View that receives an emailed reset password code and a password, and sets
    the password as credential for the user, with no extra security.

    Preconditions required for the call to succeed:
    * A PasswordResetEmailState object in the password_reset_state_db
      keyed by the received code.
    * A flag in said state object indicating that the emailed code has already
      been verified.

    As side effects, this view will:
    * Compare the received password with the hash in the session to mark
      it accordingly (as suggested or as custom);
    * Revoke all password credentials the user had;
    * Unverify any verified phone number or NIN the user previously had.

    This operation may fail due to:
    * The code does not correspond to a valid state in the db;
    * The code has expired;
    * No valid user corresponds to the eppn stored in the state;
    * Communication problems with the VCCS backend;
    * Synchronization problems with the central user db.
    """
    try:
        context = get_context(email_code=email_code)
    except StateException as e:
        return error_response(message=e.msg)

    current_app.logger.info(f"Reset password with state {email_code} using NO extra security for user {context.user}")
    return reset_user_password(user=context.user, state=context.state, password=password)


@reset_password_views.route("/extra-security-phone/", methods=["POST"])
@UnmarshalWith(ResetPasswordExtraSecPhoneSchema)
@MarshalWith(ResetPasswordResponseSchema)
def choose_extra_security_phone(email_code: str, phone_index: int) -> FluxData:
    """
    View called when the user chooses extra security (she can do that when she
    has some verified phone number). It receives an emailed reset password code
    and an index for one of the verified phone numbers, and returns info on the
    result of the attempted operation.

    Preconditions required for the call to succeed:
    * A PasswordResetEmailState object in the password_reset_state_db
      keyed by the received code.
    * A flag in said state object indicating that the emailed code has already
      been verified.
    * The user referenced in the state has at least phone_index (number) of
      verified phone numbers.

    As side effects, this operation will:
    * Copy the data in the PasswordResetEmailState to a new
      PasswordResetEmailAndPhoneState;
    * Create a new random hash as identifier code for the new state;
    * Store this code in the new state;
    * Send an SMS message with the code to the phone number corresponding to
      the received phone_index;

    This operation may fail due to:
    * The code does not correspond to a valid state in the db;
    * The code has expired;
    * No valid user corresponds to the eppn stored in the state;
    * Problems sending the SMS message
    """
    try:
        context = get_context(email_code=email_code)
    except StateException as e:
        return error_response(message=e.msg)

    if isinstance(context.state, ResetPasswordEmailAndPhoneState):
        if context.state.is_throttled(current_app.conf.throttle_sms):
            current_app.logger.error(f"Throttling reset password SMS for: {context.state.eppn}")
            return error_response(message=ResetPwMsg.send_sms_throttled)

    current_app.logger.info(f"Password reset: choose_extra_security for user {context.user}")
    # Check that the email code has been validated
    if not context.state.email_code.is_verified:
        current_app.logger.info(f"User with eppn {context.state.eppn} has not verified their email address")
        return error_response(message=ResetPwMsg.email_not_validated)

    if context.state.extra_security is None:  # please mypy
        raise ValueError(f"User {context.user} trying to reset password with extra security without alternatives")

    try:
        phone_number = context.state.extra_security["phone_numbers"][phone_index]
    except IndexError:
        current_app.logger.exception(f"Phone number at index {phone_index} does not exist")
        return error_response(message=ResetPwMsg.unknown_phone_number)

    current_app.logger.info(f"Trying to send password reset sms to user {context.user}")
    try:
        send_verify_phone_code(context.state, phone_number["number"])
    except MsgTaskFailed:
        current_app.logger.exception("Sending sms failed")
        return error_response(message=ResetPwMsg.send_sms_failure)

    current_app.stats.count(name="extra_security_phone_sent")
    return success_response(message=ResetPwMsg.send_sms_success)


@reset_password_views.route("/new-password-extra-security-phone/", methods=["POST"])
@UnmarshalWith(NewPasswordSecurePhoneRequestSchema)
@MarshalWith(ResetPasswordResponseSchema)
def set_new_pw_extra_security_phone(email_code: str, password: str, phone_code: str) -> FluxData:
    """
    View that receives an emailed reset password code, an SMS'ed reset password
    code, and a password, and sets the password as credential for the user, with
    extra security.

    Preconditions required for the call to succeed:
    * A PasswordResetEmailAndPhoneState object in the password_reset_state_db
      keyed by the received codes.
    * A flag in said state object indicating that the emailed code has already
      been verified.

    As side effects, this view will:
    * Compare the received password with the hash in the session to mark
      it accordingly (as suggested or as custom);
    * Revoke all password credentials the user had;

    This operation may fail due to:
    * The codes do not correspond to a valid state in the db;
    * Any of the codes have expired;
    * No valid user corresponds to the eppn stored in the state;
    * Communication problems with the VCCS backend;
    * Synchronization problems with the central user db.
    """
    try:
        context = get_context(email_code=email_code)
    except StateException as e:
        return error_response(message=e.msg)

    if not isinstance(context.state, ResetPasswordEmailAndPhoneState):
        # if the state is not an EmailAndPhoneState the phone code has expired
        return error_response(message=ResetPwMsg.expired_phone_code)

    if phone_code == context.state.phone_code.code:
        if not verify_phone_number(context.state):
            current_app.logger.info(f"Could not verify phone code for user {context.user}")
            return error_response(message=ResetPwMsg.phone_invalid)
        current_app.logger.info(f"Phone code verified for user {context.user}")
        current_app.stats.count(name="extra_security_phone_success")
    else:
        current_app.logger.info(f"Could not verify phone code for user {context.user}")
        return error_response(message=ResetPwMsg.unknown_phone_code)

    return reset_user_password(user=context.user, state=context.state, password=password)


@reset_password_views.route("/new-password-extra-security-token/", methods=["POST"])
@UnmarshalWith(NewPasswordSecureTokenRequestSchema)
@MarshalWith(ResetPasswordResponseSchema)
def set_new_pw_extra_security_token(
    email_code: str,
    password: str,
    token_response: str | None = None,
    authenticator_data: str | None = None,
    client_data_json: str | None = None,
    credential_id: str | None = None,
    signature: str | None = None,
) -> FluxData:
    """
    View that receives an emailed reset password code, hw token data,
    and a password, and sets the password as credential for the user, with
    extra security.

    Preconditions required for the call to succeed:
    * A PasswordResetEmailState object in the password_reset_state_db
      keyed by the received code.
    * A flag in said state object indicating that the emailed code has already
      been verified.

    As side effects, this view will:
    * Compare the received password with the hash in the session to mark
      it accordingly (as suggested or as custom);
    * Revoke all password credentials the user had;

    This operation may fail due to:
    * The codes do not correspond to a valid state in the db;
    * Any of the codes have expired;
    * No valid user corresponds to the eppn stored in the state;
    * Communication problems with the VCCS backend;
    * Synchronization problems with the central user db.
    """
    try:
        context = get_context(email_code=email_code)
    except StateException as e:
        return error_response(message=e.msg)

    # Process POSTed data
    success = False
    if authenticator_data:
        # CTAP2/Webauthn
        request_dict = {
            "credentialId": credential_id,
            "clientDataJSON": client_data_json,
            "authenticatorData": authenticator_data,
            "signature": signature,
        }
        current_app.stats.count(name="extra_security_security_key_webauthn_data_received")
        if not session.mfa_action.webauthn_state:
            current_app.logger.error("No webauthn state in session")
            current_app.stats.count(name="extra_security_security_key_webauthn_missing_session_data")
            return error_response(message=ResetPwMsg.missing_data)

        try:
            result = fido_tokens.verify_webauthn(
                user=context.user,
                request_dict=request_dict,
                rp_id=current_app.conf.fido2_rp_id,
                rp_name=current_app.conf.fido2_rp_name,
                state=session.mfa_action,
            )
            success = result.success
            if success:
                current_app.stats.count(name="extra_security_security_key_webauthn_success")
        except fido_tokens.VerificationProblem:
            pass
        finally:
            # reset webauthn_state to avoid challenge reuse
            session.mfa_action.webauthn_state = None
    else:
        current_app.logger.error(f"No webauthn data in request for {context.user}")

    if not success:
        current_app.stats.count(name="extra_security_security_key_webauthn_fail")
        return error_response(message=ResetPwMsg.fido_token_fail)

    return reset_user_password(user=context.user, state=context.state, password=password, mfa_used=success)


@reset_password_views.route("/new-password-extra-security-external-mfa/", methods=["POST"])
@UnmarshalWith(NewPasswordSecureTokenRequestSchema)
@MarshalWith(ResetPasswordResponseSchema)
def set_new_pw_extra_security_external_mfa(
    email_code: str,
    password: str,
) -> FluxData:
    try:
        context = get_context(email_code=email_code)
    except StateException as e:
        return error_response(message=e.msg)

    if session.mfa_action.success is not True:  # Explicit check that success is the boolean True
        current_app.stats.count(name="extra_security_external_mfa_fail")
        return error_response(message=ResetPwMsg.external_mfa_fail)

    current_app.logger.info(f"User used external MFA service {session.mfa_action.issuer} as extra security")
    current_app.logger.info(
        f"Issued: {session.mfa_action.authn_instant}. Authn context: {session.mfa_action.authn_context}"
    )
    # Clear mfa_action from session
    del session.mfa_action
    current_app.stats.count(name="extra_security_external_mfa_success")
    return reset_user_password(user=context.user, state=context.state, password=password, mfa_used=True)


@reset_password_views.route("/get-email-code", methods=["GET"])
def get_email_code() -> str:
    """
    Backdoor to get the email verification code in the staging or dev environments
    """
    try:
        if check_magic_cookie(current_app.conf):
            eppn = request.args.get("eppn")
            if not eppn:
                current_app.logger.info("Missing eppn argument to get_email_code")
                abort(400)
            state = current_app.password_reset_state_db.get_state_by_eppn(eppn)
            if state and state.email_code:
                return state.email_code.code
    except Exception:
        current_app.logger.exception(
            "Someone tried to use the backdoor to get the email verification code for a password reset"
        )

    abort(400)


@reset_password_views.route("/get-phone-code", methods=["GET"])
def get_phone_code() -> str:
    """
    Backdoor to get the phone verification code in the staging or dev environments
    """
    try:
        if check_magic_cookie(current_app.conf):
            eppn = request.args.get("eppn")
            if not eppn:
                current_app.logger.info("Missing eppn argument to get_phone_code")
                abort(400)
            state = current_app.password_reset_state_db.get_state_by_eppn(eppn)
            if isinstance(state, ResetPasswordEmailAndPhoneState) and state.phone_code:
                return state.phone_code.code
    except Exception:
        current_app.logger.exception(
            "Someone tried to use the backdoor to get the SMS verification code for a password reset"
        )

    abort(400)
