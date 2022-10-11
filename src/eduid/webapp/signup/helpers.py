# -*- coding: utf-8 -*-


import os
import struct
import time
from dataclasses import replace
from datetime import datetime, timedelta
from enum import Enum, unique
from typing import Optional, Union

import proquint
import requests
from flask import abort, url_for

from eduid.common.config.base import EduidEnvironment
from eduid.common.misc.timeutil import utc_now
from eduid.common.utils import urlappend
from eduid.queue.db import QueueItem, SenderInfo
from eduid.queue.db.message import EduidSignupEmail
from eduid.queue.db.message.payload import OldEduidSignupEmail
from eduid.userdb import MailAddress, NinIdentity, PhoneNumber, Profile, User
from eduid.userdb.exceptions import UserHasNotCompletedSignup, UserOutOfSync
from eduid.userdb.logs import MailAddressProofing
from eduid.userdb.signup import InviteType, SCIMReference, SignupUser
from eduid.userdb.tou import ToUEvent
from eduid.webapp.common.api.exceptions import ProofingLogFailure, VCCSBackendFailure
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.api.utils import is_throttled, save_and_sync_user, time_left
from eduid.webapp.common.authn.vccs import add_password, revoke_passwords
from eduid.webapp.common.session import session
from eduid.webapp.signup.app import current_signup_app as current_app


@unique
class SignupMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # the ToU has not been accepted
    tou_not_accepted = "signup.tou-not-accepted"
    tou_wrong_version = "signup.tou-wrong-version"
    # The email address used is already known
    email_used = "signup.email-address-used"
    # captcha not completed
    captcha_not_completed = "signup.captcha-not-completed"
    # captcha completion failed
    captcha_failed = "signup.captcha-failed"
    # unrecognized verification code
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
    # user has no password genereated in session
    password_not_generated = "signup.password-not-generated"
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
    # recaptcha not verified
    no_recaptcha = "signup.recaptcha-not-verified"
    # unrecognized verification code
    unknown_code = "signup.unknown-code"
    # the verification code has already been verified
    already_verified = "signup.already-verified"
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
        eppn = proquint.uint2quint(eppn_int)
        user = current_app.central_userdb.get_user_by_eppn(eppn)
        if not user:
            return eppn
    current_app.logger.critical("generate_eppn finished without finding a new unique eppn")
    abort(500)


def check_email_status(email: str) -> EmailStatus:
    """
    Check the email registration status.

    If the email doesn't exist in central db return 'new'.
    If the email address exists in the central db and is verified return 'address-used'.

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
        current_app.logger.warning("Incomplete user found with email {} in central userdb".format(email))

    # new signup
    if session.signup.email_verification.email is None:
        current_app.logger.debug("Registering new user with email {}".format(email))
        current_app.stats.count(name="signup_started")
        return EmailStatus.NEW

    # check if the verification code has expired
    if is_email_verification_expired(sent_ts=session.signup.email_verification.sent_at):
        current_app.logger.info("email verification expired")
        current_app.logger.debug(f"email: {email}")
        return EmailStatus.NEW

    # check if mail sending is throttled
    assert session.signup.email_verification.sent_at is not None
    if is_throttled(session.signup.email_verification.sent_at, current_app.conf.throttle_resend):
        seconds_left = time_left(session.signup.email_verification.sent_at, current_app.conf.throttle_resend)
        current_app.logger.info(f"User has been sent a verification code too recently: {seconds_left} seconds left")
        current_app.logger.debug(f"email: {email}")
        return EmailStatus.THROTTLED

    if session.signup.email_verification.email == email:
        # resend code if the user has provided the same email address
        current_app.logger.info("Resend code")
        current_app.logger.debug(f"email: {email}")
        return EmailStatus.RESEND_CODE

    # if the user has changed email address to register with, send a new code
    return EmailStatus.NEW


def verify_recaptcha(secret_key: str, captcha_response: str, user_ip: str, retries: int = 3) -> bool:
    """
    Verify the recaptcha response received from the client
    against the recaptcha API.

    :param secret_key: Recaptcha secret key
    :param captcha_response: User recaptcha response
    :param user_ip: User ip address
    :param retries: Number of times to retry sending recaptcha response

    :return: True|False
    """
    current_app.stats.count(name="recaptcha_verify_attempt")
    url = "https://www.google.com/recaptcha/api/siteverify"
    params = {"secret": secret_key, "response": captcha_response, "remoteip": user_ip}
    while retries:
        retries -= 1
        try:
            current_app.logger.debug("Sending the CAPTCHA response")
            verify_rs = requests.get(url, params=params, verify=True)
            verify_rs.raise_for_status()  # raise exception status code in 400 or 500 range
            current_app.logger.debug(f"CAPTCHA response: {verify_rs}")
            if verify_rs.json().get("success", False) is True:
                current_app.logger.info(f"Valid CAPTCHA response from {user_ip}")
                current_app.stats.count(name="recaptcha_verify_success")
                return True
            _error = verify_rs.json().get("error-codes", "Unspecified error")
            current_app.logger.info(f"Invalid CAPTCHA response from {user_ip}: {_error}")
        except requests.exceptions.RequestException as e:
            if not retries:
                current_app.logger.error("Caught RequestException while sending CAPTCHA, giving up.")
                raise e
            current_app.logger.warning("Caught RequestException while sending CAPTCHA, trying again.")
            current_app.logger.warning(e)
            time.sleep(0.5)
    return False


def send_signup_mail(email: str, verification_code: str, reference: str, use_email_link: bool = False) -> None:
    """
    Put a signup email message on the queue.
    """
    payload: Union[EduidSignupEmail, OldEduidSignupEmail]
    if use_email_link:
        # backwards compatibility
        verfication_link = urlappend(current_app.conf.signup_url, f"/code/{verification_code}")
        payload = OldEduidSignupEmail(
            email=email,
            verification_link=verfication_link,
            site_name=current_app.conf.eduid_site_name,
            site_url=current_app.conf.eduid_site_url,
            language=current_app.babel.locale_selector_func() or current_app.conf.default_language,
            reference=reference,
        )
    else:
        payload = EduidSignupEmail(
            email=email,
            verification_code=verification_code,
            site_name=current_app.conf.eduid_site_name,
            language=current_app.babel.locale_selector_func() or current_app.conf.default_language,
            reference=reference,
        )
    app_name = current_app.conf.app_name
    system_hostname = os.environ.get("SYSTEM_HOSTNAME", "")  # Underlying hosts name for containers
    hostname = os.environ.get("HOSTNAME", "")  # Actual hostname or container id
    sender_info = SenderInfo(hostname=hostname, node_id=f"{app_name}@{system_hostname}")
    expires_at = utc_now() + current_app.conf.email_verification_timeout
    discard_at = expires_at + timedelta(days=7)
    message = QueueItem(
        version=1,
        expires_at=expires_at,
        discard_at=discard_at,
        sender_info=sender_info,
        payload_type=payload.get_type(),
        payload=payload,
    )
    current_app.messagedb.save(message)
    current_app.logger.info(f"Saved signup email queue item in queue collection {current_app.messagedb._coll_name}")
    current_app.logger.debug(f"email: {email}")
    if current_app.conf.environment == EduidEnvironment.dev:
        # Debug-log the message in development environment
        current_app.logger.debug(f"Generating verification e-mail with context:\n{payload}")


def create_and_sync_user(email: str, tou_version: str, password: Optional[str] = None) -> SignupUser:
    """
    * Create a new user in the central userdb
    * Generate a new eppn
    * Record acceptance of TOU
    * Record email address and email address verification
    * Add password to the user
    * Add the password to the password db
    * Update the attribute manager db with the new account
    """
    current_app.logger.info("Creating new user")

    signup_user = SignupUser(eppn=generate_eppn())

    # Record the acceptance of the terms of use
    record_tou(signup_user=signup_user, tou_version=tou_version)
    # Add the verified email address to the user
    record_email_address(signup_user=signup_user, email=email)

    # TODO: add_password needs to understand that signup_user is a descendant from User
    if password is not None and not add_password(
        signup_user, password, application=current_app.conf.app_name, vccs_url=current_app.conf.vccs_url
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
    current_app.logger.info(f"Signup user created")
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
        current_app.logger.debug("Email {} already present in central db".format(email))
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
        reference=session.signup.email_verification.reference,
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
    if not signup_user.display_name and invite.given_name and invite.surname:
        signup_user.display_name = f"{invite.given_name} {invite.surname}"
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

    if invite.invite_type == InviteType.SCIM and isinstance(invite.invite_reference, SCIMReference):
        # update scim invite and create/update scim user
        # TODO: implement scim client
        # TODO: get invite from scim db
        # TODO: get or create user in scim db
        # TODO: add linked account to scim profile
        # TODO: check if the user should have mfa_stepup enabled
        # signup_user.profiles.add(
        #    Profile(
        #        owner=invite.invite_reference.data_owner,
        #        profile_schema="urn:ietf:params:scim:schemas:core:2.0:User",
        #        profile_data={"externalID": "USER EXTERNAL ID"},  # TODO: Fix me
        #    )
        # )
        pass

    updated_invite = replace(invite, completed_ts=utc_now())
    try:
        current_app.invite_db.save(invite=updated_invite)
        save_and_sync_user(signup_user)
    except UserOutOfSync as e:
        current_app.logger.error(f"Failed saving user {signup_user}, data out of sync")
        raise e

    if invite.finish_url:
        session.signup.invite.finish_url = invite.finish_url
    session.signup.invite.completed = True

    current_app.logger.info(f"Invite completed")
    current_app.logger.debug(f"invite_code: {invite.invite_code}")
    current_app.stats.count(name=f"{invite.invite_type.value}_invite_completed")


def is_email_verification_expired(sent_ts: Optional[datetime]) -> bool:
    if sent_ts is None:
        return True
    return utc_now() - sent_ts > current_app.conf.email_verification_timeout


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
        current_app.logger.warning("Removing old user {} with e-mail {} from signup_db".format(user, email))
        signup_db.remove_user_by_id(user.user_id)


# end of backwards compatibility
