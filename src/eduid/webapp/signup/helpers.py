import os
import struct
from dataclasses import replace
from datetime import datetime
from enum import Enum, unique
from typing import Optional

import proquint
from flask import abort

from eduid.common.config.base import EduidEnvironment
from eduid.common.misc.timeutil import utc_now
from eduid.common.models.scim_base import SCIMSchema
from eduid.common.models.scim_user import LinkedAccount as SCIMLinkedAccount
from eduid.common.models.scim_user import UserCreateRequest, UserResponse, UserUpdateRequest
from eduid.queue.client import init_queue_item
from eduid.queue.db.message import EduidSignupEmail
from eduid.userdb import MailAddress, NinIdentity, PhoneNumber, Profile, User
from eduid.userdb.exceptions import UserDoesNotExist, UserHasNotCompletedSignup, UserOutOfSync
from eduid.userdb.logs import MailAddressProofing
from eduid.userdb.signup import Invite, InviteType, SCIMReference, SignupUser
from eduid.userdb.tou import ToUEvent
from eduid.webapp.common.api.exceptions import ProofingLogFailure, VCCSBackendFailure
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.api.translation import get_user_locale
from eduid.webapp.common.api.utils import is_throttled, save_and_sync_user, time_left
from eduid.webapp.common.api.validation import is_valid_password
from eduid.webapp.common.authn.vccs import add_password, revoke_passwords
from eduid.webapp.common.session import session
from eduid.webapp.signup.app import current_signup_app as current_app


@unique
class SignupMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # the ToU has not been completed
    tou_not_completed = "signup.tou-not-completed"
    tou_wrong_version = "signup.tou-wrong-version"
    # The email address used is already known
    email_used = "signup.email-address-used"
    # captcha not completed
    captcha_not_completed = "signup.captcha-not-completed"
    # captcha completion failed
    captcha_failed = "signup.captcha-failed"
    # captcha already completed
    captcha_already_completed = "signup.captcha-already-completed"
    # captcha not requested from get-captcha endpoint
    captcha_not_requested = "signup.captcha-not-requested"
    # email verification not completed
    email_verification_not_complete = "signup.email-verification-not-complete"
    # unrecognized verification code
    email_verification_failed = "signup.email-verification-failed"
    # email verification code expired
    email_verification_expired = "signup.email-verification-expired"
    # email sending throttled
    email_throttled = "signup.email-throttled"
    # to many attempts doing email verification
    email_verification_too_many_tries = "signup.email-verification-to-many-tries"
    # user has already been created
    user_already_exists = "signup.user-already-exists"
    # user has no generated_password generated in session
    password_not_generated = "signup.password-not-generated"
    # user has provided a weak custom password
    weak_custom_password = "signup.weak-custom-password"
    # user has not registered webauthn
    webauthn_not_registered = "signup.webauthn-not-registered"
    # user has no credential
    credential_not_added = "signup.credential-not-added"
    # invite not found
    invite_not_found = "signup.invite-not-found"
    # invite already completed
    invite_already_completed = "signup.invite-already-completed"

    # backwards compatibility
    # partial success registering new account
    reg_new = "signup.registering-new"
    # The email address used is already known
    old_email_used = "signup.registering-address-used"
    # unrecognized verification code
    unknown_code = "signup.unknown-code"
    # the verification code has already been verified
    already_verified = "signup.already-verified"
    # the ToU has not been accepted
    tou_not_accepted = "signup.tou-not-accepted"
    # end of backwards compatibility


@unique
class EmailStatus(str, Enum):
    ADDRESS_USED = "address_used"
    RESEND_CODE = "resend_code"
    NEW = "new"
    THROTTLED = "throttled"


class EmailAlreadyVerifiedException(Exception):
    pass


class InviteNotFound(Exception):
    pass


def generate_eppn() -> str:
    """
    Generate a unique eduPersonPrincipalName.

    Unique is defined as 'at least it doesn't exist right now'.

    :return: eppn
    """
    for _ in range(10):
        eppn_int = struct.unpack("I", os.urandom(4))[0]
        eppn: str = proquint.uint2quint(eppn_int)
        try:
            current_app.central_userdb.get_user_by_eppn(eppn)
        except UserDoesNotExist:
            return eppn
    current_app.logger.critical("generate_eppn finished without finding a new unique eppn")
    abort(500)


def check_email_status(email: str) -> EmailStatus:
    """
    Check the email registration status.

    If the email doesn't exist in central db return 'new'.
    If the email address exists in the central db and is completed return 'address-used'.

    :return: status
    """
    try:
        am_user = current_app.central_userdb.get_user_by_mail(email)
        if am_user:
            current_app.logger.debug(f"Found user {am_user} with email {email}")
            return EmailStatus.ADDRESS_USED
        current_app.logger.debug(f"No user found with email {email} in central userdb")
    except UserHasNotCompletedSignup:
        # TODO: What is the implication of getting here? Should we just let the user signup again?
        current_app.logger.warning(f"Incomplete user found with email {email} in central userdb")

    # new signup
    if session.signup.email.address is None:
        current_app.logger.debug(f"Registering new user with email {email}")
        current_app.stats.count(name="signup_started")
        return EmailStatus.NEW

    # check if the verification code has expired
    if is_email_verification_expired(sent_ts=session.signup.email.sent_at):
        current_app.logger.info("email verification expired")
        current_app.logger.debug(f"email: {email}")
        return EmailStatus.NEW

    # check if mail sending is throttled
    assert session.signup.email.sent_at is not None
    if is_throttled(session.signup.email.sent_at, current_app.conf.throttle_resend):
        seconds_left = time_left(session.signup.email.sent_at, current_app.conf.throttle_resend)
        current_app.logger.info(f"User has been sent a verification code too recently: {seconds_left} seconds left")
        current_app.logger.debug(f"email: {email}")
        return EmailStatus.THROTTLED

    if session.signup.email.address == email:
        # resend code if the user has provided the same email address
        current_app.logger.info("Resend code")
        current_app.logger.debug(f"email: {email}")
        return EmailStatus.RESEND_CODE

    # if the user has changed email address to register with, send a new code
    return EmailStatus.NEW


def send_signup_mail(email: str, verification_code: str, reference: str) -> None:
    """
    Put a signup email message on the queue.
    """
    payload = EduidSignupEmail(
        email=email,
        verification_code=verification_code,
        site_name=current_app.conf.eduid_site_name,
        language=get_user_locale() or current_app.conf.default_language,
        reference=reference,
    )
    app_name = current_app.conf.app_name
    message = init_queue_item(
        app_name=app_name, expires_in=current_app.conf.email_verification_timeout, payload=payload
    )
    current_app.messagedb.save(message)
    current_app.logger.info(f"Saved signup email queue item in queue collection {current_app.messagedb._coll_name}")
    current_app.logger.debug(f"email: {email}")
    if current_app.conf.environment == EduidEnvironment.dev:
        # Debug-log the code and message in development environment
        current_app.logger.debug(f"code: {verification_code}")
        current_app.logger.debug(f"Generating verification e-mail with context:\n{payload}")


def create_and_sync_user(
    given_name: str,
    surname: str,
    email: str,
    tou_version: str,
    generated_password: Optional[str] = None,
    custom_password: Optional[str] = None,
) -> SignupUser:
    """
    * Create a new user in the central userdb
    * Generate a new eppn
    * Record acceptance of TOU
    * Record email address and email address verification
    * Add generated_password to the user
    * Add the generated_password to the generated_password db
    * Update the attribute manager db with the new account
    """
    current_app.logger.info("Creating new user")

    signup_user = SignupUser(eppn=generate_eppn())
    signup_user.given_name = given_name
    signup_user.surname = surname

    # Record the acceptance of the terms of use
    record_tou(signup_user=signup_user, tou_version=tou_version)
    # Add the completed email address to the user
    record_email_address(signup_user=signup_user, email=email)

    # TODO: add_password needs to understand that signup_user is a descendant from User
    if generated_password is not None or custom_password is not None:
        is_generated = custom_password is None
        password = custom_password or generated_password
        assert password is not None  # please mypy

        if not add_password(
            signup_user,
            password,
            is_generated=is_generated,
            application=current_app.conf.app_name,
            vccs_url=current_app.conf.vccs_url,
        ):
            current_app.logger.error("Failed to add a credential to user")
            current_app.logger.debug(f"signup_user: {signup_user}")
            raise VCCSBackendFailure("Failed to add a credential to user")

    try:
        save_and_sync_user(signup_user)
    except UserOutOfSync as e:
        revoke_passwords(user=signup_user, reason="UserOutOfSync during signup", application=current_app.conf.app_name)
        current_app.logger.error(f"Failed saving user {signup_user}, data out of sync")
        raise e

    current_app.stats.count(name="user_created")
    current_app.logger.info("Signup user created")
    current_app.logger.debug(f"user: {signup_user}")
    return signup_user


def record_tou(signup_user: SignupUser, tou_version: str) -> None:
    """
    Record user acceptance of terms of use.
    """
    event = ToUEvent(version=tou_version, created_by=current_app.conf.app_name)
    current_app.logger.info(
        f"Recording ToU acceptance {event.event_id} (version {event.version}) for user {signup_user} (source: {current_app.conf.app_name})"
    )
    signup_user.tou.add(event)


def record_email_address(signup_user: SignupUser, email: str) -> None:
    """
    Add user email address to user object and write proofing log entry.
    """
    user = current_app.central_userdb.get_user_by_mail(email)
    if user is not None:
        current_app.logger.debug(f"Email {email} already present in central db")
        raise EmailAlreadyVerifiedException()

    mail_address = MailAddress(
        email=email,
        created_by=current_app.conf.app_name,
        created_ts=utc_now(),
        modified_ts=utc_now(),
        is_verified=True,
        verified_ts=utc_now(),
        verified_by=current_app.conf.app_name,
        is_primary=True,
    )

    mail_address_proofing = MailAddressProofing(
        eppn=signup_user.eppn,
        created_by=current_app.conf.app_name,
        mail_address=mail_address.email,
        reference=session.signup.email.reference,
        proofing_version=current_app.conf.email_proofing_version,
    )

    if not current_app.proofing_log.save(mail_address_proofing):
        current_app.logger.error("Failed to save email address proofing log entry, aborting")
        raise ProofingLogFailure("Failed to save email address proofing log entry")

    signup_user.mail_addresses.add(mail_address)
    current_app.stats.count(name="mail_verified")


def complete_and_update_invite(user: User, invite_code: str):
    signup_user = SignupUser.from_user(user, current_app.private_userdb)
    invite = current_app.invite_db.get_invite_by_invite_code(invite_code)
    if invite is None:
        current_app.logger.error(f"Invite with code {invite_code} not found")
        raise InviteNotFound("Invite not found")

    # set user attributes from invite data if not already set
    if invite.given_name and not signup_user.given_name:
        signup_user.given_name = invite.given_name
    if invite.surname and not signup_user.surname:
        signup_user.surname = invite.surname
    if invite.preferred_language and not signup_user.language:
        signup_user.language = invite.preferred_language
    if invite.nin and not signup_user.identities.nin:
        signup_user.identities.add(NinIdentity(number=invite.nin, created_by=current_app.conf.app_name))
    for address in invite.mail_addresses:
        if signup_user.mail_addresses.find(address.email) is None:
            signup_user.mail_addresses.add(MailAddress(email=address.email, created_by=current_app.conf.app_name))
    for number in invite.phone_numbers:
        if signup_user.phone_numbers.find(number.number) is None:
            signup_user.phone_numbers.add(PhoneNumber(number=number.number, created_by=current_app.conf.app_name))

    if invite.invite_type == InviteType.SCIM:
        if not isinstance(invite.invite_reference, SCIMReference):
            raise RuntimeError("Invite reference is not a SCIMReference")

        scim_user = update_or_create_scim_user(invite=invite, signup_user=signup_user)
        # add scim profile to eduid user
        signup_user.profiles.add(
            Profile(
                owner=invite.invite_reference.data_owner,
                profile_schema="urn:ietf:params:scim:schemas:core:2.0:User",
                profile_data={"externalID": scim_user.external_id},
            )
        )

    updated_invite = replace(invite, completed_ts=utc_now())
    try:
        current_app.invite_db.save(invite=updated_invite, is_in_database=True)
        save_and_sync_user(signup_user)
    except UserOutOfSync as e:
        current_app.logger.error(f"Failed saving user {signup_user}, data out of sync")
        raise e

    if invite.finish_url:
        session.signup.invite.finish_url = invite.finish_url
    session.signup.invite.completed = True

    current_app.logger.info("Invite completed")
    current_app.logger.debug(f"invite_code: {invite.invite_code}")
    current_app.stats.count(name=f"{invite.invite_type.value}_invite_completed")


def update_or_create_scim_user(invite: Invite, signup_user: SignupUser) -> UserResponse:
    if not isinstance(invite.invite_reference, SCIMReference):
        raise RuntimeError("Invite reference is not a SCIMReference")

    with current_app.get_scim_client_for(data_owner=invite.invite_reference.data_owner) as client:
        # update scim invite and create/update scim user
        scim_invite = client.get_invite(invite_id=invite.invite_reference.scim_id)
        scim_user = client.get_user_by_external_id(external_id=scim_invite.external_id)
        if scim_user is None:
            # create a new scim user
            external_id = scim_invite.external_id or f"{signup_user.eppn}@{invite.invite_reference.data_owner}"
            scim_user_create_req = UserCreateRequest(schemas=[SCIMSchema.CORE_20_USER], external_id=external_id)
            scim_user = client.create_user(scim_user_create_req)

        # update scim users missing attributes
        update_user = UserUpdateRequest(**scim_user.dict(exclude={"meta"}))
        # names
        name_updates = {}
        if update_user.name.given_name is None:
            name_updates["given_name"] = invite.given_name
        if update_user.name.family_name is None:
            name_updates["family_name"] = invite.surname
        if name_updates:
            update_user = update_user.copy(update={"name": update_user.name.copy(update=name_updates).dict()})
        # preferred language
        if update_user.preferred_language is None:
            update_user = update_user.copy(update={"preferred_language": invite.preferred_language})
        # emails
        if not update_user.emails:
            update_user = update_user.copy(
                update={
                    "emails": [
                        {"value": address.email, "primary": address.primary} for address in invite.mail_addresses
                    ]
                }
            )
        # phone numbers
        if not update_user.phone_numbers:
            update_user = update_user.copy(
                update={
                    "phone_numbers": [
                        {"value": number.number, "primary": number.primary} for number in invite.phone_numbers
                    ]
                }
            )
        # linked account
        parameters = dict()
        # mfa stepup
        if scim_invite.nutid_invite_v1.enable_mfa_stepup:
            parameters = {"mfa_stepup": True}
        eduid_linked_account = SCIMLinkedAccount(
            issuer=current_app.conf.eduid_scope,
            value=f"{signup_user.eppn}@{current_app.conf.eduid_scope}",
            parameters=parameters,
        )
        assert update_user.nutid_user_v1 is not None  # please mypy
        linked_accounts = update_user.nutid_user_v1.dict().get("linked_accounts", [])
        linked_accounts.append(eduid_linked_account)
        update_user = update_user.copy(
            update={"nutid_user_v1": update_user.nutid_user_v1.copy(update={"linked_accounts": linked_accounts}).dict()}
        )
        return client.update_user(user=update_user, version=scim_user.meta.version)


def is_email_verification_expired(sent_ts: Optional[datetime]) -> bool:
    if sent_ts is None:
        return True
    return utc_now() - sent_ts > current_app.conf.email_verification_timeout


def is_valid_custom_password(custom_password: Optional[str]) -> bool:
    if custom_password is None:
        return False

    # collect user_info and check against zxcvbn
    user_info_data = [session.signup.name.given_name, session.signup.name.surname, session.signup.email.address]
    user_info = [item for item in user_info_data if item]
    try:
        is_valid_password(
            custom_password,
            user_info=user_info,
            min_entropy=current_app.conf.password_entropy,
            min_score=current_app.conf.min_zxcvbn_score,
        )
    except ValueError:
        return False

    return True


# backwards compatibility
def remove_users_with_mail_address(email: str) -> None:
    """
    Remove all users with a certain (confirmed) e-mail address from signup_db.
    When syncing of signed up users fail, they remain in the signup_db in a completed state
    (no pending mail address). This prevents the user from signing up again, and they can't
    use their new eduid account either since it is not synced to the central userdb.
    An option would have been to sync the user again, now, but that was deemed more
    surprising to the user so instead we remove all the unsynced users from signup_db
    so the user can do a new signup.
    :param email: E-mail address
    :return: None
    """
    signup_db = current_app.private_userdb
    # The e-mail address does not exist in userdb (checked by caller), so if there exists a user
    # in signup_db with this (non-pending) e-mail address, it is probably left-overs from a
    # previous signup where the sync to userdb failed. Clean away all such users in signup_db
    # and continue like this was a completely new signup.
    completed_users = signup_db.get_users_by_mail(email)
    for user in completed_users:
        current_app.logger.warning(f"Removing old user {user} with e-mail {email} from signup_db")
        signup_db.remove_user_by_id(user.user_id)


# end of backwards compatibility
