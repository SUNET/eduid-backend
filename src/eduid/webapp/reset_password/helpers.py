import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from enum import unique
from typing import Any

from fido2.webauthn import UserVerificationRequirement
from flask import render_template

from eduid.common.config.base import EduidEnvironment
from eduid.common.misc.timeutil import utc_now
from eduid.common.utils import generate_password, get_short_hash
from eduid.queue.client import init_queue_item
from eduid.queue.db.message.payload import EduidResetPasswordEmail
from eduid.userdb.exceptions import UserDoesNotExist
from eduid.userdb.logs import MailAddressProofing, PhoneNumberProofing
from eduid.userdb.reset_password import ResetPasswordEmailAndPhoneState, ResetPasswordEmailState, ResetPasswordUser
from eduid.userdb.reset_password.element import CodeElement
from eduid.userdb.user import User
from eduid.webapp.common.api.exceptions import ThrottledException
from eduid.webapp.common.api.messages import FluxData, TranslatableMsg, error_response, success_response
from eduid.webapp.common.api.translation import get_user_locale
from eduid.webapp.common.api.utils import check_password_hash, get_zxcvbn_terms, make_short_code, save_and_sync_user
from eduid.webapp.common.api.validation import is_valid_password
from eduid.webapp.common.authn import fido_tokens
from eduid.webapp.common.authn.vccs import reset_password
from eduid.webapp.common.session import session
from eduid.webapp.reset_password.app import current_reset_password_app as current_app


@unique
class ResetPwMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # The user has sent a code that corresponds to no known password reset
    # request
    state_not_found = "resetpw.state-not-found"
    # Some required input data is empty
    missing_data = "resetpw.missing-data"
    # The user has sent an SMS'ed code that corresponds to no known password
    # reset request
    unknown_phone_code = "resetpw.phone-code-unknown"
    # The phone number choice is out of bounds
    unknown_phone_number = "resetpw.phone-number-unknown"
    # The user has sent a code that has expired
    expired_email_code = "resetpw.expired-email-code"
    # The user has sent an SMS'ed code that has expired
    expired_phone_code = "resetpw.expired-phone-code"
    # There was some problem sending the email with the code.
    email_send_failure = "resetpw.email-send-failure"
    # A new code has been generated and sent by email successfully
    email_send_throttled = "resetpw.email-throttled"
    # Sending the email has been throttled.
    reset_pw_initialized = "resetpw.reset-pw-initialized"
    # The password has been successfully reset
    pw_reset_success = "resetpw.pw-reset-success"
    # The password has _NOT_ been successfully reset
    pw_reset_fail = "resetpw.pw-reset-fail"
    # There was some problem sending the SMS with the (extra security) code.
    send_sms_throttled = "resetpw.sms-throttled"
    # Sending the SMS with the (extra security) code has been throttled.
    send_sms_failure = "resetpw.send-sms-failed"
    # A new (extra security) code has been generated and sent by SMS
    # successfully
    send_sms_success = "resetpw.send-sms-success"
    # The phone number has not been verified. Should not happen.
    phone_invalid = "resetpw.phone-invalid"
    # No user was found corresponding to the password reset state. Should not
    # happen.
    user_not_found = "resetpw.user-not-found"
    # The email address has not been verified. Should not happen.
    email_not_validated = "resetpw.email-not-validated"
    # User has not completed signup
    invalid_user = "resetpw.invalid-user"
    # extra security with fido tokens failed - wrong token
    fido_token_fail = "resetpw.fido-token-fail"
    # extra security with external MFA service failed
    external_mfa_fail = "resetpw.external-mfa-fail"
    # The password chosen is too weak
    resetpw_weak = "resetpw.weak-password"
    # The browser already has a session for another user
    invalid_session = "resetpw.invalid_session"
    # captcha completed
    captcha_completed = "resetpw.captcha-completed"
    # captcha answer failed
    captcha_failed = "resetpw.captcha-failed"
    # captcha not completed
    captcha_not_completed = "resetpw.captcha-not-completed"
    # captcha already completed
    captcha_already_completed = "resetpw.captcha-already-completed"
    # captcha not requested
    captcha_not_requested = "resetpw.captcha-not-requested"


class StateException(Exception):
    def __init__(self, msg: TranslatableMsg | None = None) -> None:
        self.msg = msg


@dataclass
class ResetPasswordContext:
    state: ResetPasswordEmailState | ResetPasswordEmailAndPhoneState
    user: User


def get_context(email_code: str) -> ResetPasswordContext:
    """
    Use a email code to load reset-password state from the database.

    :param email_code: User supplied password reset code
    :return: ResetPasswordContext instance
    """
    state = get_pwreset_state(email_code)

    user = current_app.central_userdb.get_user_by_eppn(state.eppn)
    if not user:
        # User has been removed before reset password was completed
        current_app.logger.error(f"User not found for state {state.email_code}")
        raise StateException(msg=ResetPwMsg.user_not_found)

    return ResetPasswordContext(state=state, user=user)


def get_pwreset_state(email_code: str) -> ResetPasswordEmailState | ResetPasswordEmailAndPhoneState:
    """
    get the password reset state for the provided code

    raises BadCode in case of problems
    """
    mail_expiration_time = current_app.conf.email_code_timeout
    sms_expiration_time = current_app.conf.phone_code_timeout
    state = current_app.password_reset_state_db.get_state_by_email_code(email_code)
    if not state:
        current_app.logger.info(f"State not found: {email_code}")
        current_app.stats.count(name="state_not_found", value=1)
        raise StateException(msg=ResetPwMsg.state_not_found)

    current_app.logger.debug(f"Found state using email_code {email_code}: {state}")

    if state.email_code.is_expired(mail_expiration_time):
        current_app.logger.info(f"State expired: {email_code}")
        current_app.stats.count(name="email_code_expired", value=1)
        raise StateException(msg=ResetPwMsg.expired_email_code)

    if isinstance(state, ResetPasswordEmailAndPhoneState) and state.phone_code.is_expired(sms_expiration_time):
        current_app.logger.info(f"Phone code expired for state: {email_code}")
        # Revert the state to EmailState to allow the user to choose extra security again
        current_app.password_reset_state_db.remove_state(state)
        state = ResetPasswordEmailState(eppn=state.eppn, email_address=state.email_address, email_code=state.email_code)
        current_app.password_reset_state_db.save(state, is_in_database=False)
        current_app.stats.count(name="phone_code_expired", value=1)
        raise StateException(msg=ResetPwMsg.expired_phone_code)
    return state


def is_generated_password(password: str) -> bool:
    if check_password_hash(password, session.reset_password.generated_password_hash):
        current_app.logger.info("Generated password used")
        current_app.stats.count(name="generated_password_used")
        return True
    current_app.logger.info("Custom password used")
    current_app.stats.count(name="custom_password_used")
    return False


def send_password_reset_mail(email_address: str) -> ResetPasswordEmailState:
    """
    Put a reset password email message on the queue.
    """

    user = current_app.central_userdb.get_user_by_mail(email_address)
    if not user:
        current_app.logger.error(f"Cannot send reset password mail to an unknown email address: {email_address}")
        raise UserDoesNotExist(f"User with e-mail address {email_address} not found")

    # User found, check if a state already exists
    state = current_app.password_reset_state_db.get_state_by_eppn(eppn=user.eppn)
    _is_in_db = state is not None
    if state and not state.email_code.is_expired(timeout=current_app.conf.email_code_timeout):
        # Let the user only send one mail every throttle_resend time period
        if state.is_throttled(current_app.conf.throttle_resend):
            raise ThrottledException(state=state)
        # If a state is found and not expired, just send another message with the same code
        # Update created_ts to give the user another email_code_timeout seconds to complete the password reset
        state.email_code.created_ts = utc_now()
    else:
        # create a new state
        state = ResetPasswordEmailState(
            eppn=user.eppn,
            email_address=email_address,
            email_code=CodeElement(
                code=make_short_code(digits=current_app.conf.email_code_length),
                created_by=current_app.conf.app_name,
                is_verified=False,
            ),
        )
        _is_in_db = False
    current_app.password_reset_state_db.save(state, is_in_database=_is_in_db)

    # send the reset password email to all verified email addresses
    to_addresses = [address.email for address in user.mail_addresses.verified]
    for email_address in to_addresses:
        payload = EduidResetPasswordEmail(
            email=email_address,
            verification_code=state.email_code.code,
            password_reset_timeout=current_app.conf.email_code_timeout // timedelta(hours=1),
            site_name=current_app.conf.eduid_site_name,
            language=get_user_locale() or current_app.conf.default_language,
            reference=state.email_reference,
        )

        message = init_queue_item(
            app_name=current_app.conf.app_name, expires_in=current_app.conf.email_code_timeout, payload=payload
        )
        current_app.messagedb.save(message)
        current_app.logger.info(
            f"Saved rest password email queue item in queue collection {current_app.messagedb._coll_name}"
        )
        current_app.logger.debug(f"email: {email_address}")
        if current_app.conf.environment == EduidEnvironment.dev:
            # Debug-log the code and message in development environment
            current_app.logger.debug(f"code: {state.email_code.code}")
            current_app.logger.debug(f"Generating verification e-mail with context:\n{payload}")

    current_app.logger.info("Queued password reset email(s)")
    current_app.logger.debug(f"Mail addresses: {to_addresses}")

    return state


def generate_suggested_password(password_length: int) -> str:
    """
    The suggested password is hashed and saved in session to avoid form hijacking
    """
    password = generate_password(length=password_length)
    password = " ".join([password[i * 4 : i * 4 + 4] for i in range(math.ceil(len(password) / 4))])

    return password


def extra_security_used(
    state: ResetPasswordEmailState | ResetPasswordEmailAndPhoneState, mfa_used: bool = False
) -> bool:
    """
    Check if any extra security method was used

    :param state: Password reset state
    :param mfa_used: If a security key or external MFA was used
    :return: True|False
    """
    if state.email_code.is_verified and mfa_used:
        return True
    if isinstance(state, ResetPasswordEmailAndPhoneState):
        return state.email_code.is_verified and state.phone_code.is_verified
    return False


def unverify_user(user: ResetPasswordUser) -> None:
    """
    :param user: User object

    Unverify the users verified information (phone numbers and NIN)
    """
    # Phone numbers
    verified_phone_numbers = user.phone_numbers.verified
    if verified_phone_numbers:
        current_app.logger.info(f"Unverifying phone numbers for user {user}")
        if user.phone_numbers.primary:
            user.phone_numbers.primary.is_primary = False
        for phone_number in verified_phone_numbers:
            phone_number.is_verified = False
            current_app.logger.info("Phone number unverified")
            current_app.logger.debug(f"Phone number: {phone_number.number}")
            current_app.stats.count(name="unverified_phone", value=1)
    # identities
    verified_identities = user.identities.verified
    if verified_identities:
        current_app.logger.info("Unverifying identities for user")
        for identity in verified_identities:
            identity.is_verified = False
            current_app.logger.info("identity unverified")
            current_app.logger.debug(f"identity: {identity}")
            current_app.stats.count(name=f"unverified_{identity.identity_type}", value=1)


def reset_user_password(
    user: User,
    state: ResetPasswordEmailState | ResetPasswordEmailAndPhoneState,
    password: str,
    mfa_used: bool = False,
) -> FluxData:
    """
    :param user: the user
    :param state: Password reset state
    :param password: Plain text password
    :param mfa_used: If a security key or external MFA was used as extra security
    """
    # Check the password complexity is enough
    user_info = get_zxcvbn_terms(user)
    try:
        is_valid_password(
            password,
            user_info=user_info,
            min_entropy=current_app.conf.password_entropy,
            min_score=current_app.conf.min_zxcvbn_score,
        )
    except ValueError:
        return error_response(message=ResetPwMsg.resetpw_weak)

    reset_password_user = ResetPasswordUser.from_user(user, private_userdb=current_app.private_userdb)

    # If no extra security is used, all verified information (except email addresses) is set to not verified
    if not extra_security_used(state, mfa_used):
        current_app.stats.count(name="no_extra_security", value=1)
        current_app.logger.info(f"No extra security used by user {user}")
        unverify_user(reset_password_user)

    _res = reset_password(
        reset_password_user,
        new_password=password,
        is_generated=is_generated_password(password=password),
        application="security",
        vccs_url=current_app.conf.vccs_url,
    )

    if not _res:
        # Uh oh, reset password failed. Credentials _might_ have been reset in the backend but we don't know.
        current_app.stats.count(name="password_reset_fail", value=1)
        current_app.logger.error(f"Reset password failed for user {reset_password_user}")
        return error_response(message=ResetPwMsg.pw_reset_fail)

    # Undo termination if user is terminated
    if reset_password_user.terminated is not None:
        current_app.logger.info(f"Revoking termination for user: {user.terminated}")
        reset_password_user.terminated = None

    save_and_sync_user(reset_password_user)
    current_app.stats.count(name="password_reset_success", value=1)
    current_app.logger.info(f"Reset password successful for user {reset_password_user}")

    current_app.logger.info(f"Password reset done, removing state for {user}")
    current_app.password_reset_state_db.remove_state(state)
    return success_response(message=ResetPwMsg.pw_reset_success)


def get_extra_security_alternatives(user: User) -> dict:
    """
    :param user: The user
    :return: Dict of alternatives
    """
    alternatives: dict[str, Any] = {}

    if user.identities.nin is not None and user.identities.nin.is_verified:
        alternatives["external_mfa"] = True

    if user.phone_numbers.verified:
        verified_phone_numbers = [
            {"number": item.number, "index": n} for n, item in enumerate(user.phone_numbers.verified)
        ]
        alternatives["phone_numbers"] = verified_phone_numbers

    tokens = fido_tokens.get_user_credentials(user, mfa_approved=True)

    if tokens:
        alternatives["tokens"] = fido_tokens.start_token_verification(
            user=user,
            fido2_rp_id=current_app.conf.fido2_rp_id,
            fido2_rp_name=current_app.conf.fido2_rp_name,
            state=session.mfa_action,
            user_verification=UserVerificationRequirement.REQUIRED,
        ).model_dump()

    return alternatives


def mask_alternatives(alternatives: dict) -> dict:
    """
    :param alternatives: Extra security alternatives collected from user
    :return: Masked extra security alternatives
    """
    if alternatives:
        # Phone numbers
        masked_phone_numbers = []
        for phone_number in alternatives.get("phone_numbers", []):
            number = phone_number["number"]
            masked_number = "{}{}".format("X" * (len(number) - 2), number[len(number) - 2 :])
            masked_phone_numbers.append({"number": masked_number, "index": phone_number["index"]})

        alternatives["phone_numbers"] = masked_phone_numbers
    return alternatives


def verify_email_address(state: ResetPasswordEmailState) -> bool:
    """
    :param state: Password reset state
    """
    user = current_app.central_userdb.get_user_by_eppn(state.eppn)
    if not user:
        current_app.logger.error(f"Could not find user {user}")
        return False

    proofing_element = MailAddressProofing(
        eppn=user.eppn,
        created_by="security",
        mail_address=state.email_address,
        reference=state.reference,
        proofing_version="2013v1",
    )

    if current_app.proofing_log.save(proofing_element):
        state.email_code.is_verified = True
        current_app.password_reset_state_db.save(state)
        current_app.logger.info(f"Email code marked as used for {user}")
        return True

    return False


def send_verify_phone_code(state: ResetPasswordEmailState, phone_number: str) -> None:
    phone_state = ResetPasswordEmailAndPhoneState.from_email_state(
        state, phone_number=phone_number, phone_code=get_short_hash()
    )
    current_app.password_reset_state_db.save(phone_state)

    template = "reset_password_sms.txt.jinja2"
    context = {"verification_code": phone_state.phone_code.code}
    send_sms(
        phone_number=phone_state.phone_number, text_template=template, reference=phone_state.reference, context=context
    )
    current_app.logger.info(f"Sent password reset sms to user with eppn: {state.eppn}")
    if current_app.conf.debug and current_app.conf.environment in [EduidEnvironment.staging, EduidEnvironment.dev]:
        current_app.logger.debug(f"Sent password reset sms with code: {phone_state.phone_code.code}")
    current_app.logger.debug(f"Phone number: {phone_state.phone_number}")


def send_sms(phone_number: str, text_template: str, reference: str, context: Mapping[str, Any] | None = None) -> None:
    """
    :param phone_number: the recipient of the sms
    :param text_template: message as a jinja template
    :param context: template context
    :param reference: Audit reference to help cross reference audit log and events
    """
    _context = {
        "site_url": current_app.conf.eduid_site_url,
        "site_name": current_app.conf.eduid_site_name,
    }
    if context is not None:
        _context.update(context)

    message = render_template(text_template, **_context)
    current_app.msg_relay.sendsms(recipient=phone_number, message=message, reference=reference)


def verify_phone_number(state: ResetPasswordEmailAndPhoneState) -> bool:
    """
    :param state: Password reset state
    """

    user = current_app.central_userdb.get_user_by_eppn(state.eppn)
    if not user:
        current_app.logger.error(f"Could not find user {user}")
        return False

    proofing_element = PhoneNumberProofing(
        eppn=user.eppn,
        created_by="security",
        phone_number=state.phone_number,
        reference=state.reference,
        proofing_version="2013v1",
    )
    if current_app.proofing_log.save(proofing_element):
        state.phone_code.is_verified = True
        current_app.password_reset_state_db.save(state)
        current_app.logger.info(f"Phone code marked as used for {user}")
        return True

    return False


def email_state_to_response_payload(state: ResetPasswordEmailState) -> dict[str, Any]:
    _throttled = int(state.throttle_time_left(current_app.conf.throttle_resend).total_seconds())
    if _throttled < 0:
        _throttled = 0
    return {
        "email": state.email_address,
        "email_code_timeout": int(current_app.conf.email_code_timeout.total_seconds()),
        "throttled_seconds": _throttled,
        "throttled_max": int(current_app.conf.throttle_resend.total_seconds()),
    }
