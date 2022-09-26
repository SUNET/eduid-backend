# -*- coding: utf-8 -*-
from uuid import uuid4

from flask import Blueprint, abort, request

from eduid.common.misc.timeutil import utc_now
from eduid.userdb import User
from eduid.userdb.exceptions import UserOutOfSync
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.exceptions import ProofingLogFailure
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.csrf import EmptyRequest
from eduid.webapp.common.api.utils import get_short_hash, throttle_time_left
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
    send_signup_mail,
    verify_recaptcha,
)
from eduid.webapp.signup.schemas import (
    AcceptTouRequest,
    CaptchaCompleteRequest,
    CaptchaResponse,
    EmailSchema,
    InviteCodeRequest,
    InviteDataResponse,
    SignupStatusResponse,
    VerifyEmailSchema,
)

signup_views = Blueprint('signup', __name__, url_prefix='', template_folder='templates')


@signup_views.route('/register-email', methods=['POST'])
@UnmarshalWith(EmailSchema)
@MarshalWith(SignupStatusResponse)
def register_email(email: str):
    """
    Register a with new email address.
    """
    current_app.logger.info('Registering email')
    current_app.logger.debug(f'email address: {email}')

    if not session.signup.captcha_completed:
        # don't allow registration without captcha completion
        # this is so that a malicious user can't send a lot of emails or enumerate email addresses already registered
        return error_response(message=SignupMsg.captcha_not_completed)

    # TODO: backwards compatibility, remove next release
    # if a signup is in progress, let the user continue it
    signup_user = current_app.private_userdb.get_user_by_pending_mail_address(email)
    if signup_user is not None:
        assert signup_user.pending_mail_address is not None  # please mypy
        current_app.logger.debug("Found user {} with pending email {} in signup db".format(signup_user, email))
        session.signup.email_verification.email = signup_user.pending_mail_address.email
        session.signup.email_verification.code = signup_user.pending_mail_address.verification_code
        session.signup.email_verification.sent_at = signup_user.pending_mail_address.modified_ts
    # end backwards compatibility

    email_status = check_email_status(email)
    if email_status == EmailStatus.ADDRESS_USED:
        current_app.logger.info('Email address already used')
        return error_response(payload=session.signup.to_dict(), message=SignupMsg.email_used)
    if email_status == EmailStatus.THROTTLED:
        current_app.logger.info('Email sending throttled')
        return error_response(payload=session.signup.to_dict(), message=SignupMsg.email_throttled)
    if email_status == EmailStatus.NEW:
        current_app.logger.info('Starting new signup')
        session.signup.email_verification.email = email
        session.signup.email_verification.code = get_short_hash(entropy=current_app.conf.email_verification_code_length)
        session.signup.email_verification.sent_at = utc_now()
        session.signup.email_verification.reference = str(uuid4())

    # send email to the user
    if email_status in [EmailStatus.NEW, EmailStatus.RESEND_CODE]:
        current_app.logger.info('Sending verification email')
        assert session.signup.email_verification.email is not None  # please mypy
        assert session.signup.email_verification.code is not None  # please mypy
        assert session.signup.email_verification.reference is not None  # please mypy
        send_signup_mail(
            email=session.signup.email_verification.email,
            verification_code=session.signup.email_verification.code,
            reference=session.signup.email_verification.reference,
        )
        current_app.stats.count(name='verification_email_sent')

    return success_response(payload=session.signup.to_dict())


@signup_views.route('/verify-email', methods=['POST'])
@UnmarshalWith(VerifyEmailSchema)
@MarshalWith(SignupStatusResponse)
def verify_email(verification_code: str):
    """
    Verify the email address.
    """
    current_app.logger.info('Verifying email')
    current_app.logger.debug(f'email address: {session.signup.email_verification.email}')
    current_app.logger.debug(f'verification code: {verification_code}')

    # ignore verification attempts if there has been to many wrong attempts
    if (
        session.signup.email_verification.wrong_code_attempts
        >= current_app.conf.email_verification_max_wrong_code_attempts
    ):
        current_app.logger.info('Too many wrong verification attempts')
        # TODO: should we reset the users signup session to allow them to start over
        #   or should we just let them do another captcha?
        return error_response(message=SignupMsg.email_verification_too_many_tries)

    if not session.signup.captcha_completed:
        return error_response(message=SignupMsg.captcha_not_completed)

    if (
        is_email_verification_expired(sent_ts=session.signup.email_verification.sent_at)
        or session.signup.email_verification.code is None
        or session.signup.email_verification.code != verification_code
    ):
        current_app.logger.info('Verification failed')
        session.signup.email_verification.wrong_code_attempts += 1
        return error_response(message=SignupMsg.email_verification_failed)

    session.signup.email_verification.verified = True
    return success_response(payload=session.signup.to_dict())


@signup_views.route('/accept-tou', methods=['POST'])
@UnmarshalWith(AcceptTouRequest)
@MarshalWith(SignupStatusResponse)
def accept_tou(tou_accepted: bool, tou_version: str):
    """
    Accept the Terms of Use.
    """
    current_app.logger.info('Accepting ToU')
    if not tou_accepted:
        current_app.logger.info('ToU not accepted')
        return error_response(message=SignupMsg.tou_not_accepted)

    current_app.logger.info('ToU accepted')
    session.signup.tou_accepted = True
    session.signup.tou_version = tou_version
    return success_response(payload=session.signup.to_dict())


@signup_views.route('/captcha', methods=['GET'])
# @UnmarshalWith()
@MarshalWith(CaptchaResponse)
def captcha_request() -> FluxData:
    # TODO: respond with either new captcha or recaptcha
    pass


@signup_views.route('/captcha', methods=['POST'])
@UnmarshalWith(CaptchaCompleteRequest)
@MarshalWith(SignupStatusResponse)
def captcha_response(recaptcha_response: str) -> FluxData:
    """
    Check for humanness even at level AL1.
    """
    current_app.logger.info('Checking captcha')

    captcha_verified = False

    # add a backdoor to bypass recaptcha checks for humanness,
    # to be used in testing environments for automated integration tests.
    if check_magic_cookie(current_app.conf):
        current_app.logger.info('Using BACKDOOR to verify reCaptcha during signup!')
        captcha_verified = True

    # common path with no backdoor
    if recaptcha_response and not captcha_verified:
        remote_ip = request.remote_addr
        if current_app.conf.recaptcha_public_key and current_app.conf.recaptcha_private_key:
            captcha_verified = verify_recaptcha(current_app.conf.recaptcha_private_key, recaptcha_response, remote_ip)
        else:
            current_app.logger.info('Missing configuration for reCaptcha!')

    if not captcha_verified:
        current_app.logger.info('Captcha failed')
        return error_response(message=SignupMsg.captcha_failed)

    current_app.logger.info('Captcha verified')
    session.signup.captcha_completed = True
    return success_response(payload=session.signup.to_dict())


@signup_views.route('/get-password', methods=['GET'])
@MarshalWith(SignupStatusResponse)
def get_password() -> FluxData:
    current_app.logger.info('Password requested')
    session.signup.generated_password = generate_password()
    session.signup.credential_added = True
    return success_response(payload=session.signup.to_dict())


@signup_views.route('/create-user', methods=['POST'])
@UnmarshalWith(EmptyRequest)
@MarshalWith(SignupStatusResponse)
def create_user() -> FluxData:
    current_app.logger.info('Creating user')

    if session.common.eppn or session.signup.user_created:
        # do not try to create a new user if the user already exists
        current_app.logger.error('User already created')
        current_app.logger.debug(f'eppn: {session.common.eppn}')
        current_app.logger.debug(f'user created: {session.signup.user_created}')
        return error_response(message=SignupMsg.user_already_exists)

    if not session.signup.captcha_completed:
        current_app.logger.error('Captcha not completed')
        return error_response(message=SignupMsg.captcha_not_completed)
    if not session.signup.email_verification.verified:
        current_app.logger.error('Email not verified')
        return error_response(message=SignupMsg.email_verification_not_complete)
    if not session.signup.tou_accepted:
        current_app.logger.error('ToU not accepted')
        return error_response(message=SignupMsg.tou_not_accepted)
    if not session.signup.credential_added:
        current_app.logger.error('Credential not added')
        return error_response(message=SignupMsg.credential_not_added)

    assert session.signup.email_verification.email is not None  # please mypy
    assert session.signup.tou_version is not None  # please mypy
    try:
        signup_user = create_and_sync_user(
            email=session.signup.email_verification.email,
            password=session.signup.generated_password,
            tou_version=session.signup.tou_version,
        )
    except EmailAlreadyVerifiedException:
        return error_response(message=SignupMsg.email_used)
    except ProofingLogFailure:
        return error_response(message=CommonMsg.temp_problem)
    except UserOutOfSync:
        return error_response(message=CommonMsg.out_of_sync)

    session.signup.user_created = True
    session.common.eppn = signup_user.eppn

    return success_response(payload=session.signup.to_dict())


@signup_views.route('/invite-data', methods=['POST'])
@UnmarshalWith(InviteCodeRequest)
@MarshalWith(InviteDataResponse)
def get_invite(invite_code: str):
    invite = current_app.invite_db.get_invite_by_invite_code(code=invite_code)
    if invite is None:
        current_app.logger.error('Invite not found')
        current_app.logger.debug(f'invite_code: {invite_code}')
        return error_response(message=SignupMsg.invite_not_found)

    return {
        'invite_type': invite.invite_type,
        'inviter_name': invite.inviter_name,
        'email': invite.get_primary_mail_address(),
        'preferred_language': invite.preferred_language,
        'expires_at': invite.expires_at,
        'given_name': invite.given_name,
        'surname': invite.surname,
        'finish_url': invite.finish_url,
    }


@signup_views.route('/accept-invite', methods=['POST'])
@UnmarshalWith(InviteCodeRequest)
def accept_invite(invite_code: str) -> FluxData:
    invite = current_app.invite_db.get_invite_by_invite_code(code=invite_code)
    if invite is None:
        current_app.logger.error('Invite not found')
        current_app.logger.debug(f'invite_code: {invite_code}')
        return error_response(message=SignupMsg.invite_not_found)

    if invite.completed_ts is not None:
        current_app.logger.error('Invite already completed')
        current_app.logger.debug(f'invite_code: {invite_code}')
        return error_response(message=SignupMsg.invite_already_completed)

    if invite.get_primary_mail_address() is not None:
        session.signup.email_verification.email = invite.get_primary_mail_address()

    if invite.send_email is True:
        # user reached the invite endpoint after receiving an email
        # we can now set the email as verified
        session.signup.email_verification.verified = True
        session.signup.email_verification.sent_at = invite.created_ts

    session.signup.invite.code = invite.invite_code
    session.signup.invite.initiated_signup = True
    return success_response(payload=session.signup.to_dict())


@signup_views.route('/complete-invite', methods=['POST'])
@MarshalWith(SignupStatusResponse)
def complete_invite() -> FluxData:
    current_app.logger.info('Completing invite')

    if not session.common.eppn or session.signup.invite.initiated_signup is False:
        return success_response(payload=session.signup.to_dict())

    user = current_app.central_userdb.get_user_by_eppn(eppn=session.common.eppn)
    if user is None:
        return error_response(message=CommonMsg.temp_problem)

    assert session.signup.invite.code is not None  # please mypy
    try:
        complete_and_update_invite(user=user, invite_code=session.signup.invite.code)
    except InviteNotFound:
        current_app.logger.info('Invite not found')
        return error_response(message=SignupMsg.invite_not_found)
    except UserOutOfSync:
        return error_response(message=CommonMsg.out_of_sync)

    current_app.logger.info('Invite completed for new user')
    current_app.stats.count(name='invite_completed_new_user')
    return success_response(payload=session.signup.to_dict())


@signup_views.route('/complete-invite-existing-user', methods=['POST'])
@MarshalWith(SignupStatusResponse)
@require_user
def complete_invite_existing_user(user: User) -> FluxData:
    current_app.logger.info('Completing invite for existing user')

    if session.signup.invite.initiated_signup is False:
        return success_response(payload=session.signup.to_dict())

    assert session.signup.invite.code is not None  # please mypy
    try:
        complete_and_update_invite(user=user, invite_code=session.signup.invite.code)
    except InviteNotFound:
        return error_response(message=SignupMsg.invite_not_found)
    except UserOutOfSync:
        return error_response(message=CommonMsg.out_of_sync)

    current_app.logger.info('Invite completed for existing user')
    current_app.stats.count(name='invite_completed_existing_user')
    return success_response(payload=session.signup.to_dict())


# BACKDOOR for testing
@signup_views.route('/get-code', methods=['GET'])
def get_email_code():
    """
    Backdoor to get the email verification code in the staging or dev environments
    """
    try:
        if check_magic_cookie(current_app.conf):
            email = request.args.get('email')
            if not email:
                current_app.logger.error('Missing email')
                abort(400)
            if session.signup.email_verification.email == email:
                return session.signup.email_verification.code
    except Exception:
        current_app.logger.exception("Someone tried to use the backdoor to get the email verification code for signup")

    abort(400)
