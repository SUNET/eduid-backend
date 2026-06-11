from datetime import datetime

from eduid.common.misc.timeutil import utc_now
from eduid.userdb import User
from eduid.userdb.credentials import Webauthn
from eduid.userdb.credentials.external import (
    BankIDCredential,
    EidasCredential,
    ExternalCredential,
    FrejaCredential,
    SwedenConnectCredential,
    TrustFramework,
)
from eduid.userdb.identity import (
    IdentityProofingMethod,
    IdentityType,
    PridPersistence,
)
from eduid.userdb.logs.element import (
    BankIDProofing,
    FrejaEIDForeignProofing,
    FrejaEIDNINProofing,
    MFATokenBankIDProofing,
    MFATokenEIDASProofing,
    MFATokenFrejaEIDForeignProofing,
    MFATokenFrejaEIDProofing,
    MFATokenProofing,
    SwedenConnectEIDASProofing,
    SwedenConnectProofing,
)
from eduid.userdb.signup import SignupUser
from eduid.webapp.common.api.exceptions import ProofingLogFailure
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import (
    AuthnRequestRef,
    ExternalMfaSignupBankIDIdentity,
    ExternalMfaSignupEIDASIdentity,
    ExternalMfaSignupFrejaEIDForeignIdentity,
    ExternalMfaSignupFrejaEIDIdentity,
    ExternalMfaSignupIdentity,
    ExternalMfaSignupSwedenConnectIdentity,
    OIDCState,
    RP_AuthnRequest,
    SignupExternalMfa,
    SP_AuthnRequest,
)
from eduid.webapp.signup.app import current_signup_app as current_app

__author__ = "lundberg"


def build_external_credential(framework: TrustFramework, loa: str, created_by: str) -> ExternalCredential:
    """Build the appropriate ExternalCredential subclass for the given TrustFramework."""
    match framework:
        case TrustFramework.SWECONN:
            return SwedenConnectCredential(level=loa, created_by=created_by)
        case TrustFramework.EIDAS:
            return EidasCredential(level=loa, created_by=created_by)
        case TrustFramework.BANKID:
            return BankIDCredential(level=loa, created_by=created_by)
        case TrustFramework.FREJA:
            return FrejaCredential(level=loa, created_by=created_by)
        case _:
            raise ValueError(f"Unsupported TrustFramework: {framework}")


def identity_proofing_method_for_framework(framework: TrustFramework) -> IdentityProofingMethod:
    """Map the external MFA TrustFramework to the IdentityProofingMethod to record
    on the verified NinIdentity/EIDASIdentity. Required so that the IdP DIGG LoA 2
    assurance check recognizes the proofing method."""
    match framework:
        case TrustFramework.BANKID:
            return IdentityProofingMethod.BANKID
        case TrustFramework.SWECONN | TrustFramework.EIDAS:
            return IdentityProofingMethod.SWEDEN_CONNECT
        case TrustFramework.FREJA:
            return IdentityProofingMethod.FREJA_EID
        case _:
            raise ValueError(f"Unsupported TrustFramework: {framework}")


def identity_proofing_version_for_framework(framework: TrustFramework) -> str:
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


def _credential_proofing_version_for_identity(identity: ExternalMfaSignupIdentity) -> str:
    """Return the configured credential proofing version string for the given identity type."""
    match identity:
        case ExternalMfaSignupSwedenConnectIdentity() | ExternalMfaSignupBankIDIdentity():
            return current_app.conf.security_key_proofing_version
        case ExternalMfaSignupEIDASIdentity():
            return current_app.conf.security_key_foreign_eid_proofing_version
        case ExternalMfaSignupFrejaEIDIdentity():
            return current_app.conf.security_key_freja_eid_proofing_version
        case ExternalMfaSignupFrejaEIDForeignIdentity():
            return current_app.conf.security_key_foreign_eid_proofing_version
        case _:
            current_app.logger.exception(f"Unsupported identity type: {identity}")
            raise ValueError(f"Unsupported external mfa identity: {type(identity)}")


def maybe_verify_webauthn_credential(
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

    if not _write_credential_verification_proofing_log(signup_user, webauthn.key, external_mfa):
        return

    credential.is_verified = True
    credential.verified_by = current_app.conf.app_name
    credential.verified_ts = now
    credential.proofing_method = current_app.conf.security_key_proofing_method
    credential.proofing_version = _credential_proofing_version_for_identity(external_mfa.ident)
    current_app.logger.info(f"Marked webauthn credential {webauthn.key} as verified via external MFA during signup")


def _write_credential_verification_proofing_log(
    signup_user: SignupUser, credential_id: str, external_mfa: SignupExternalMfa
) -> bool:
    """Write a proofing log entry for a webauthn credential verified via external MFA during signup."""
    app_name = current_app.conf.app_name
    version = _credential_proofing_version_for_identity(external_mfa.ident)

    entry: (
        MFATokenProofing
        | MFATokenBankIDProofing
        | MFATokenEIDASProofing
        | MFATokenFrejaEIDProofing
        | MFATokenFrejaEIDForeignProofing
    )

    match external_mfa.ident:
        case ExternalMfaSignupBankIDIdentity():
            entry = MFATokenBankIDProofing(
                created_by=app_name,
                eppn=signup_user.eppn,
                given_name=external_mfa.ident.given_name,
                key_id=credential_id,
                nin=external_mfa.ident.nin,
                proofing_version=version,
                surname=external_mfa.ident.surname,
                transaction_id=external_mfa.ident.transaction_id,
            )
        case ExternalMfaSignupSwedenConnectIdentity():
            entry = MFATokenProofing(
                authn_context_class=external_mfa.ident.authn_context_class,
                created_by=app_name,
                eppn=signup_user.eppn,
                given_name=external_mfa.ident.given_name,
                issuer=external_mfa.ident.issuer,
                key_id=credential_id,
                nin=external_mfa.ident.nin,
                proofing_version=version,
                surname=external_mfa.ident.surname,
            )
        case ExternalMfaSignupEIDASIdentity():
            entry = MFATokenEIDASProofing(
                authn_context_class=external_mfa.ident.authn_context_class,
                country_code=external_mfa.ident.country_code,
                created_by=app_name,
                date_of_birth=external_mfa.ident.date_of_birth.date().isoformat(),
                eidas_person_identifier=external_mfa.ident.eidas_person_identifier,
                eppn=signup_user.eppn,
                given_name=external_mfa.ident.given_name,
                issuer=external_mfa.ident.issuer,
                key_id=credential_id,
                prid=external_mfa.ident.prid,
                prid_persistence=external_mfa.ident.prid_persistence,
                proofing_version=version,
                surname=external_mfa.ident.surname,
                transaction_identifier=external_mfa.ident.transaction_id,
            )
        case ExternalMfaSignupFrejaEIDIdentity():
            entry = MFATokenFrejaEIDProofing(
                created_by=app_name,
                document_number=external_mfa.ident.document_number,
                document_type=external_mfa.ident.document_type,
                eppn=signup_user.eppn,
                given_name=external_mfa.ident.given_name,
                key_id=credential_id,
                nin=external_mfa.ident.nin,
                proofing_version=version,
                surname=external_mfa.ident.surname,
                transaction_id=external_mfa.ident.transaction_id,
                user_id=external_mfa.ident.user_id,
            )
        case ExternalMfaSignupFrejaEIDForeignIdentity():
            entry = MFATokenFrejaEIDForeignProofing(
                country_code=external_mfa.ident.country_code,
                created_by=app_name,
                date_of_birth=external_mfa.ident.date_of_birth.date().isoformat(),
                document_number=external_mfa.ident.document_number,
                document_type=external_mfa.ident.document_type,
                eppn=signup_user.eppn,
                given_name=external_mfa.ident.given_name,
                issuing_country=external_mfa.ident.issuing_country,
                key_id=credential_id,
                proofing_version=version,
                surname=external_mfa.ident.surname,
                transaction_id=external_mfa.ident.transaction_id,
                user_id=external_mfa.ident.user_id,
            )
        case _:
            current_app.logger.debug(f"Unknown external mfa identity: {external_mfa.ident}")
            current_app.logger.error("Unknown external identity — no credential proofing log written")
            return False

    if not current_app.proofing_log.save(entry):
        current_app.logger.error(f"Failed to save credential verification proofing log for {signup_user.eppn}")
        raise ProofingLogFailure("Failed to save credential verification proofing log")
    return True


def write_external_mfa_proofing_log(signup_user: SignupUser, external_mfa: SignupExternalMfa) -> bool:
    """Write a proofing log entry for an identity verified via external MFA during signup."""

    app_name = current_app.conf.app_name
    method = external_mfa.method
    version = identity_proofing_version_for_framework(external_mfa.ident.framework)
    entry: (
        BankIDProofing
        | SwedenConnectProofing
        | SwedenConnectEIDASProofing
        | FrejaEIDNINProofing
        | FrejaEIDForeignProofing
    )

    match external_mfa.ident:
        case ExternalMfaSignupBankIDIdentity():
            entry = BankIDProofing(
                eppn=signup_user.eppn,
                created_by=app_name,
                proofing_version=version,
                nin=external_mfa.ident.nin,
                given_name=external_mfa.ident.given_name,
                surname=external_mfa.ident.surname,
                transaction_id=external_mfa.ident.transaction_id,
            )
        case ExternalMfaSignupSwedenConnectIdentity():
            entry = SwedenConnectProofing(
                eppn=signup_user.eppn,
                created_by=app_name,
                proofing_version=version,
                issuer=external_mfa.ident.issuer,
                authn_context_class=external_mfa.ident.authn_context_class,
                nin=external_mfa.ident.nin,
                given_name=external_mfa.ident.given_name,
                surname=external_mfa.ident.surname,
            )
        case ExternalMfaSignupEIDASIdentity():
            entry = SwedenConnectEIDASProofing(
                eppn=signup_user.eppn,
                created_by=app_name,
                proofing_version=version,
                issuer=external_mfa.ident.issuer,
                authn_context_class=external_mfa.ident.authn_context_class,
                prid=external_mfa.ident.prid,
                prid_persistence=external_mfa.ident.prid_persistence,
                eidas_person_identifier=external_mfa.ident.eidas_person_identifier,
                transaction_identifier=external_mfa.ident.transaction_id,
                given_name=external_mfa.ident.given_name,
                surname=external_mfa.ident.surname,
                date_of_birth=external_mfa.ident.date_of_birth.date().isoformat(),
                country_code=external_mfa.ident.country_code,
            )
        case ExternalMfaSignupFrejaEIDIdentity():
            entry = FrejaEIDNINProofing(
                eppn=signup_user.eppn,
                created_by=app_name,
                proofing_version=version,
                nin=external_mfa.ident.nin,
                given_name=external_mfa.ident.given_name,
                surname=external_mfa.ident.surname,
                user_id=external_mfa.ident.user_id,
                document_type=external_mfa.ident.document_type,
                document_number=external_mfa.ident.document_number,
                transaction_id=external_mfa.ident.transaction_id,
            )
        case ExternalMfaSignupFrejaEIDForeignIdentity():
            entry = FrejaEIDForeignProofing(
                eppn=signup_user.eppn,
                created_by=app_name,
                proofing_method=method,
                proofing_version=version,
                given_name=external_mfa.ident.given_name,
                surname=external_mfa.ident.surname,
                date_of_birth=external_mfa.ident.date_of_birth.date().isoformat(),
                country_code=external_mfa.ident.country_code,
                user_id=external_mfa.ident.user_id,
                administrative_number=external_mfa.ident.personal_identity_number
                or "freja_no_identity_number_provided",
                document_type=external_mfa.ident.document_type,
                document_number=external_mfa.ident.document_number,
                issuing_country=external_mfa.ident.issuing_country,
                transaction_id=external_mfa.ident.transaction_id,
            )
        case _:
            current_app.logger.error(f"Unknown identity {external_mfa.ident} — no proofing log written")
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


def existing_user_for_identity(ident: ExternalMfaSignupIdentity) -> User | None:
    """Return an existing verified user matching the given NIN or eIDAS PRID, or None.

    For eIDAS, matches both the active verified identity (where the same PRID is
    currently a user's verified EIDAS identity) and the locked identity (where the
    user has since re-verified with a rotated PRID but the original is still locked).
    eIDAS PRIDs with persistence B/C rotate over time so an exact miss does not
    guarantee no duplicate — we log a warning in that case.
    """
    match ident:
        case (
            ExternalMfaSignupBankIDIdentity()
            | ExternalMfaSignupFrejaEIDIdentity()
            | ExternalMfaSignupSwedenConnectIdentity()
        ):
            return current_app.central_userdb.get_user_by_nin(ident.nin)
        case ExternalMfaSignupEIDASIdentity():
            users = current_app.central_userdb.get_users_by_identity(
                identity_type=IdentityType.EIDAS,
                key="prid",
                value=ident.prid,
            )
            if users:
                if len(users) > 1:
                    current_app.logger.warning(f"Multiple users matched PRID {ident.prid}")
                return users[0]
            locked = current_app.central_userdb.get_users_by_locked_identity(
                identity_type=IdentityType.EIDAS,
                key="prid",
                value=ident.prid,
            )
            if locked:
                if len(locked) > 1:
                    current_app.logger.warning(f"Multiple users matched locked PRID {ident.prid}")
                return locked[0]
            if ident.prid_persistence in (PridPersistence.B, PridPersistence.C):
                current_app.logger.warning(
                    f"Signup eIDAS PRID has persistence {ident.prid_persistence.value} with no exact match; "
                    "cannot rule out duplicate of an existing user whose PRID has rotated"
                )
        case ExternalMfaSignupFrejaEIDForeignIdentity():
            users = current_app.central_userdb.get_users_by_identity(
                identity_type=IdentityType.FREJA,
                key="user_id",
                value=ident.user_id,
            )
            if users:
                if len(users) > 1:
                    current_app.logger.warning(f"Multiple users matched Freja user_id {ident.user_id}")
                return users[0]
    return None
