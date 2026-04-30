import os
import struct
from dataclasses import replace
from datetime import datetime
from enum import StrEnum, unique

import proquint  # type: ignore[import-untyped]
from flask import abort

from eduid.common.config.base import EduidEnvironment
from eduid.common.misc.timeutil import utc_now
from eduid.common.models.scim_base import Email, SCIMSchema
from eduid.common.models.scim_base import PhoneNumber as ScimPhoneNumber
from eduid.common.models.scim_user import LinkedAccount as SCIMLinkedAccount
from eduid.common.models.scim_user import NutidUserExtensionV1, UserCreateRequest, UserResponse, UserUpdateRequest
from eduid.queue.client import init_queue_item
from eduid.queue.db.message import EduidSignupEmail
from eduid.userdb import MailAddress, NinIdentity, PhoneNumber, Profile, User
from eduid.userdb.credentials import Webauthn
from eduid.userdb.credentials.external import (
    BankIDCredential,
    EidasCredential,
    ExternalCredential,
    FrejaCredential,
    SwedenConnectCredential,
    TrustFramework,
)
from eduid.userdb.exceptions import UserDoesNotExist, UserOutOfSync
from eduid.userdb.identity import (
    EIDASIdentity,
    EIDASLoa,
    FrejaIdentity,
    IdentityProofingMethod,
    PridPersistence,
)
from eduid.userdb.logs import MailAddressProofing
from eduid.userdb.logs.element import (
    ForeignIdProofingLogElement,
    NinEIDProofingLogElement,
)
from eduid.userdb.signup import Invite, InviteType, SCIMReference, SignupUser
from eduid.userdb.tou import ToUEvent
from eduid.webapp.common.api.exceptions import ProofingLogFailure, VCCSBackendFailure
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.api.translation import get_user_locale
from eduid.webapp.common.api.utils import is_throttled, save_and_sync_user, time_left
from eduid.webapp.common.api.validation import is_valid_password
from eduid.webapp.common.authn.vccs import add_password, revoke_passwords
from eduid.webapp.common.authn.webauthn import AuthenticatorInformation, save_webauthn_proofing_log
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import SignupExternalMfa
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
    # webauthn registration failed or not completed
    webauthn_registration_failed = "signup.webauthn-registration-failed"
    # user has not set name (given_name and surname)
    name_not_set = "signup.name-not-set"
    # user has no credential
    credential_not_added = "signup.credential-not-added"
    # webauthn credential is not discoverable and no password was set
    password_required = "signup.password-required"
    # invite not found
    invite_not_found = "signup.invite-not-found"
    # invite already completed
    invite_already_completed = "signup.invite-already-completed"
    # IdP request ref not found in session
    idp_request_ref_not_found = "signup.idp-request-ref-not-found"

    # external MFA signup
    external_mfa_not_found = "signup.external-mfa-not-found"
    external_mfa_not_verified = "signup.external-mfa-not-verified"
    external_mfa_too_old = "signup.external-mfa-too-old"
    external_mfa_already_consumed = "signup.external-mfa-already-consumed"
    external_mfa_wrong_action = "signup.external-mfa-wrong-action"
    identity_already_registered = "signup.identity-already-registered"

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
class EmailStatus(StrEnum):
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
    am_user = current_app.central_userdb.get_user_by_mail(email)
    if am_user:
        current_app.logger.debug(f"Found user {am_user} with email {email}")
        return EmailStatus.ADDRESS_USED
    current_app.logger.debug(f"No user found with email {email} in central userdb")

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


def get_eppn() -> str:
    """Generate and store an eppn in the signup session if not already present."""
    if session.signup.eppn is None:
        session.signup.eppn = generate_eppn()
    return session.signup.eppn


def create_and_sync_user(
    given_name: str,
    surname: str,
    email: str,
    tou_version: str,
    generated_password: str | None = None,
    custom_password: str | None = None,
    webauthn: Webauthn | None = None,
    webauthn_authenticator_info: AuthenticatorInformation | None = None,
    external_mfa: SignupExternalMfa | None = None,
    webauthn_registered_at: datetime | None = None,
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

    signup_user = SignupUser(eppn=get_eppn())
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
            version=2 if current_app.conf.password_v2_upgrade_enabled else 1,
        ):
            current_app.logger.error("Failed to add a credential to user")
            current_app.logger.debug(f"signup_user: {signup_user}")
            raise VCCSBackendFailure("Failed to add a credential to user")

    # Write webauthn proofing log after user is saved (eppn exists in DB)
    if webauthn is not None:
        if webauthn.mfa_approved:
            # Need to write proofing log for mfa_approved credentials
            assert webauthn_authenticator_info is not None
            if not save_webauthn_proofing_log(
                eppn=signup_user.eppn,
                authenticator_info=webauthn_authenticator_info,
                proofing_log=current_app.proofing_log,
                app_name=current_app.conf.app_name,
                proofing_version=current_app.conf.webauthn_proofing_version,
                proofing_method=current_app.conf.webauthn_proofing_method,
            ):
                current_app.logger.error("Failed to save webauthn proofing log")
                raise ProofingLogFailure("Failed to save webauthn proofing log")
        # add credential to user
        signup_user.credentials.add(webauthn)

    if external_mfa is not None and _write_external_mfa_proofing_log(signup_user, external_mfa):
        record_user_identity(signup_user=signup_user, external_mfa=external_mfa)

    # If the user registered a security key and verified their identity via external MFA,
    # and both happened recently enough, mark the security key as verified too.
    _maybe_verify_webauthn_credential(signup_user, webauthn, webauthn_registered_at, external_mfa)

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
        f"Recording ToU acceptance {event.event_id} (version {event.version}) for user {signup_user} "
        f"(source: {current_app.conf.app_name})"
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


def complete_and_update_invite(user: User, invite_code: str) -> None:
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
        update_user = UserUpdateRequest(**scim_user.model_dump(exclude={"meta"}))
        # names
        name_updates = {}
        if update_user.name.given_name is None:
            name_updates["given_name"] = invite.given_name
        if update_user.name.family_name is None:
            name_updates["family_name"] = invite.surname
        if name_updates:
            update_user = update_user.model_copy(
                update={"name": update_user.name.model_copy(update=name_updates).model_dump()}
            )
        # preferred language
        if update_user.preferred_language is None:
            update_user = update_user.model_copy(update={"preferred_language": invite.preferred_language})
        # emails
        if not update_user.emails:
            update_user = update_user.model_copy(
                update={
                    "emails": [Email(value=address.email, primary=address.primary) for address in invite.mail_addresses]
                }
            )
        # phone numbers
        if not update_user.phone_numbers:
            update_user = update_user.model_copy(
                update={
                    "phone_numbers": [
                        ScimPhoneNumber(value=number.number, primary=number.primary) for number in invite.phone_numbers
                    ]
                }
            )
        # linked account
        parameters = {}
        # mfa stepup
        if scim_invite.nutid_invite_v1.enable_mfa_stepup:
            parameters = {"mfa_stepup": True}
        eduid_linked_account = SCIMLinkedAccount(
            issuer=current_app.conf.eduid_scope,
            value=f"{signup_user.eppn}@{current_app.conf.eduid_scope}",
            parameters=parameters,
        )
        assert update_user.nutid_user_v1 is not None  # please mypy
        linked_accounts = update_user.nutid_user_v1.model_dump().get("linked_accounts", [])
        linked_accounts.append(eduid_linked_account)
        update_user = update_user.model_copy(
            update={
                "nutid_user_v1": NutidUserExtensionV1(
                    profiles=update_user.nutid_user_v1.profiles, linked_accounts=linked_accounts
                )
            }
        )
        return client.update_user(user=update_user, version=scim_user.meta.version)


def is_email_verification_expired(sent_ts: datetime | None) -> bool:
    if sent_ts is None:
        return True
    return utc_now() - sent_ts > current_app.conf.email_verification_timeout


def is_valid_custom_password(custom_password: str | None) -> bool:
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


def get_webauthn_credential_data() -> tuple[Webauthn, AuthenticatorInformation]:
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
        authenticator_id=wn.authenticator_id,
        attestation_format=wn.attestation_format,
        user_present=wn.user_present,
        user_verified=wn.user_verified,
        user_verification_methods=wn.user_verification_methods,
        key_protection=wn.key_protection,
    )
    return webauthn_credential, webauthn_authenticator_info


def build_external_credential(framework: TrustFramework, loa: str, created_by: str) -> ExternalCredential:
    """Build the appropriate ExternalCredential subclass for the given TrustFramework."""
    match framework:
        case TrustFramework.SWECONN:
            cred: ExternalCredential = SwedenConnectCredential(level=loa)
        case TrustFramework.EIDAS:
            cred = EidasCredential(level=loa)
        case TrustFramework.BANKID:
            cred = BankIDCredential(level=loa)
        case TrustFramework.FREJA:
            cred = FrejaCredential(level=loa)
        case _:
            raise ValueError(f"Unsupported TrustFramework: {framework}")
    cred.created_by = created_by
    return cred


def _identity_proofing_method_for_framework(framework: TrustFramework) -> IdentityProofingMethod:
    """Map the external MFA TrustFramework to the IdentityProofingMethod to record
    on the verified NinIdentity/EIDASIdentity. Required so that the IdP DIGG LoA 2
    assurance check recognises the proofing method."""
    match framework:
        case TrustFramework.BANKID:
            return IdentityProofingMethod.BANKID
        case TrustFramework.SWECONN | TrustFramework.EIDAS:
            return IdentityProofingMethod.SWEDEN_CONNECT
        case TrustFramework.FREJA:
            return IdentityProofingMethod.FREJA_EID
        case _:
            raise ValueError(f"Unsupported TrustFramework: {framework}")


def _proofing_version_for_framework(framework: TrustFramework) -> str:
    """Return the configured proofing version string for the given TrustFramework."""
    match framework:
        case TrustFramework.SWECONN:
            return current_app.conf.freja_proofing_version
        case TrustFramework.EIDAS:
            return current_app.conf.foreign_eid_proofing_version
        case TrustFramework.BANKID:
            return current_app.conf.bankid_proofing_version
        case TrustFramework.FREJA:
            return current_app.conf.freja_eid_proofing_version
        case _:
            raise ValueError(f"Unsupported TrustFramework: {framework}")


def _maybe_verify_webauthn_credential(
    signup_user: SignupUser,
    webauthn: Webauthn | None,
    webauthn_registered_at: datetime | None,
    external_mfa: SignupExternalMfa | None,
) -> None:
    """Mark a webauthn credential as verified if an external MFA identity verification
    was performed recently enough and the security key was also registered recently enough.

    Both the external MFA authn_instant and the webauthn registration timestamp must be
    within ``credential_verify_max_age`` of the current time.
    """
    if webauthn is None or external_mfa is None or webauthn_registered_at is None:
        return

    max_age = current_app.conf.credential_verify_max_age
    now = utc_now()

    if now - external_mfa.authn_instant > max_age:
        current_app.logger.info("External MFA authn_instant too old for credential verification")
        return

    if now - webauthn_registered_at > max_age:
        current_app.logger.info("Webauthn registration too old for credential verification")
        return

    credential = signup_user.credentials.find(webauthn.key)
    if credential is None:
        current_app.logger.error(f"Could not find webauthn credential {webauthn.key} on signup user")
        return

    if not _write_credential_verification_proofing_log(signup_user, external_mfa):
        return

    credential.is_verified = True
    credential.verified_by = current_app.conf.app_name
    credential.verified_ts = now
    credential.proofing_method = current_app.conf.security_key_proofing_method
    credential.proofing_version = current_app.conf.security_key_proofing_version
    current_app.logger.info(f"Marked webauthn credential {webauthn.key} as verified via external MFA during signup")


def _write_credential_verification_proofing_log(signup_user: SignupUser, external_mfa: SignupExternalMfa) -> bool:
    """Write a proofing log entry for a webauthn credential verified via external MFA during signup."""
    app_name = current_app.conf.app_name
    method = external_mfa.app_name
    version = _proofing_version_for_framework(external_mfa.framework)

    entry: NinEIDProofingLogElement | ForeignIdProofingLogElement

    if external_mfa.nin:
        entry = NinEIDProofingLogElement(
            eppn=signup_user.eppn,
            created_by=app_name,
            proofing_method=method,
            proofing_version=version,
            nin=external_mfa.nin,
            given_name=external_mfa.given_name,
            surname=external_mfa.surname,
        )
    elif external_mfa.eidas_prid or external_mfa.freja_user_id:
        if external_mfa.date_of_birth is None:
            current_app.logger.error(
                "date_of_birth is needed for ForeignIdProofingLogElement — no credential proofing log written"
            )
            return False
        entry = ForeignIdProofingLogElement(
            eppn=signup_user.eppn,
            created_by=app_name,
            proofing_method=method,
            proofing_version=version,
            given_name=external_mfa.given_name,
            surname=external_mfa.surname,
            date_of_birth=external_mfa.date_of_birth.isoformat(),
            country_code=external_mfa.country_code,
        )
    else:
        current_app.logger.error(
            "SignupExternalMfa has neither nin, eidas_prid, nor freja_user_id — no credential proofing log written"
        )
        return False

    if not current_app.proofing_log.save(entry):
        current_app.logger.error(f"Failed to save credential verification proofing log for {signup_user.eppn}")
        raise ProofingLogFailure("Failed to save credential verification proofing log")
    return True


def _write_external_mfa_proofing_log(signup_user: SignupUser, external_mfa: SignupExternalMfa) -> bool:
    """Write a proofing log entry for an identity verified via external MFA during signup.

    Uses the generic NinEIDProofingLogElement / ForeignIdProofingLogElement classes,
    since the signup backend only has what `SignupExternalMfa` carries — no SAML
    transaction_id, no Freja document info, etc. Those live in the original
    SP_AuthnRequest / RP_AuthnRequest written by the MFA webapp at ACS time and are
    not propagated into session.signup.external_mfa by design.
    """
    app_name = current_app.conf.app_name
    # Record the source MFA webapp as proofing_method, version mapped from TrustFramework
    method = external_mfa.app_name
    version = _proofing_version_for_framework(external_mfa.framework)

    entry: NinEIDProofingLogElement | ForeignIdProofingLogElement

    if external_mfa.nin:
        entry = NinEIDProofingLogElement(
            eppn=signup_user.eppn,
            created_by=app_name,
            proofing_method=method,
            proofing_version=version,
            nin=external_mfa.nin,
            given_name=external_mfa.given_name,
            surname=external_mfa.surname,
        )
    elif external_mfa.eidas_prid or external_mfa.freja_user_id:
        if external_mfa.date_of_birth is None:
            current_app.logger.error("Missing date_of_birth for ForeignIdProofingLogElement")
            return False
        entry = ForeignIdProofingLogElement(
            eppn=signup_user.eppn,
            created_by=app_name,
            proofing_method=method,
            proofing_version=version,
            given_name=external_mfa.given_name,
            surname=external_mfa.surname,
            date_of_birth=external_mfa.date_of_birth.isoformat(),
            country_code=external_mfa.country_code,
        )
    else:
        current_app.logger.error(
            "SignupExternalMfa has neither nin, eidas_prid, nor freja_user_id — no proofing log written"
        )
        return False

    if not current_app.proofing_log.save(entry):
        current_app.logger.error(f"Failed to save external MFA proofing log for {signup_user.eppn}")
        raise ProofingLogFailure("Failed to save external MFA proofing log")
    return True


def lookup_external_mfa_authn(app_name: str, authn_id: str) -> SP_AuthnRequest | RP_AuthnRequest | None:
    match app_name:
        case "freja_eid":
            return session.freja_eid.rp.authns.get(OIDCState(authn_id))
        case "eidas":
            return session.eidas.sp.authns.get(AuthnRequestRef(authn_id))
        case "bankid":
            return session.bankid.sp.authns.get(AuthnRequestRef(authn_id))
        case "samleid":
            return session.samleid.sp.authns.get(AuthnRequestRef(authn_id))
        case _:
            return None


def validate_external_mfa_authn(
    authn: SP_AuthnRequest | RP_AuthnRequest,
) -> SignupMsg | None:
    if authn.frontend_action != FrontendAction.SIGNUP_EXTERNAL_MFA:
        return SignupMsg.external_mfa_wrong_action
    if authn.error:
        return SignupMsg.external_mfa_not_verified
    if authn.external_mfa_signup_identity is None:
        return SignupMsg.external_mfa_not_verified
    if authn.consumed:
        return SignupMsg.external_mfa_already_consumed
    if authn.authn_instant is None:
        return SignupMsg.external_mfa_not_verified
    max_age = current_app.conf.frontend_action_authn_parameters[FrontendAction.SIGNUP_EXTERNAL_MFA].max_age
    if utc_now() - authn.authn_instant > max_age:
        return SignupMsg.external_mfa_too_old
    if err := _validate_signup_identity(authn.external_mfa_signup_identity):
        return err
    return None


def _validate_signup_identity(ident: ExternalMfaSignupIdentity) -> SignupMsg | None:
    """Require exactly one identity discriminator (NIN, eIDAS PRID, or Freja user_id) and its
    required companion fields. Prevents downstream 500s in ``create_and_sync_user``
    when the upstream ACS handler failed to populate a usable identity."""
    has_nin = bool(ident.nin)
    has_prid = bool(ident.eidas_prid)
    has_freja = bool(ident.freja_user_id)
    if sum([has_nin, has_prid, has_freja]) != 1:
        current_app.logger.error(
            f"External MFA signup identity has invalid discriminators: "
            f"nin={has_nin}, eidas_prid={has_prid}, freja_user_id={has_freja}"
        )
        return SignupMsg.external_mfa_not_verified
    if has_prid and (ident.country_code is None or ident.date_of_birth is None):
        current_app.logger.error("External MFA signup identity with eidas_prid is missing required fields")
        current_app.logger.debug(f"country_code: {ident.country_code}")
        current_app.logger.debug(f"date_of_birth: {ident.date_of_birth}")
        return SignupMsg.external_mfa_not_verified
    if has_freja and (
        ident.country_code is None
        or ident.freja_registration_level is None
        or ident.freja_loa_level is None
        or ident.date_of_birth is None
    ):
        current_app.logger.error("External MFA signup identity with freja_user_id is missing required fields")
        current_app.logger.debug(f"country_code: {ident.country_code}")
        current_app.logger.debug(f"freja_registration_level: {ident.freja_registration_level}")
        current_app.logger.debug(f"freja_loa_level: {ident.freja_loa_level}")
        current_app.logger.debug(f"date_of_birth: {ident.date_of_birth}")
        return SignupMsg.external_mfa_not_verified
    return None


def existing_user_for_identity(
    nin: str | None,
    eidas_prid: str | None,
    prid_persistence: PridPersistence | None = None,
    freja_user_id: str | None = None,
) -> User | None:
    """Return an existing verified user matching the given NIN or eIDAS PRID, or None.

    For eIDAS, matches both the active verified identity (where the same PRID is
    currently a user's verified EIDAS identity) and the locked identity (where the
    user has since re-verified with a rotated PRID but the original is still locked).
    eIDAS PRIDs with persistence B/C rotate over time so an exact miss does not
    guarantee no duplicate — we log a warning in that case.
    """
    if nin:
        return current_app.central_userdb.get_user_by_nin(nin)
    if eidas_prid:
        users = current_app.central_userdb.get_users_by_identity(
            identity_type=IdentityType.EIDAS,
            key="prid",
            value=eidas_prid,
        )
        if users:
            if len(users) > 1:
                current_app.logger.warning(f"Multiple users matched PRID {eidas_prid}")
            return users[0]
        locked = current_app.central_userdb.get_users_by_locked_identity(
            identity_type=IdentityType.EIDAS,
            key="prid",
            value=eidas_prid,
        )
        if locked:
            if len(locked) > 1:
                current_app.logger.warning(f"Multiple users matched locked PRID {eidas_prid}")
            return locked[0]
        if prid_persistence in (PridPersistence.B, PridPersistence.C):
            current_app.logger.warning(
                f"Signup eIDAS PRID has persistence {prid_persistence.value} with no exact match; "
                "cannot rule out duplicate of an existing user whose PRID has rotated"
            )
    if freja_user_id:
        users = current_app.central_userdb.get_users_by_identity(
            identity_type=IdentityType.FREJA,
            key="user_id",
            value=freja_user_id,
        )
        if users:
            if len(users) > 1:
                current_app.logger.warning(f"Multiple users matched Freja user_id {freja_user_id}")
            return users[0]
    return None


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
