from dataclasses import dataclass
from datetime import datetime

from eduid.common.config.base import ProofingConfigMixin
from eduid.common.rpc.exceptions import AmTaskFailed
from eduid.userdb import EIDASIdentity, User
from eduid.userdb.credentials import Credential
from eduid.userdb.element import ElementKey
from eduid.userdb.exceptions import LockedIdentityViolation
from eduid.userdb.identity import EIDASLoa, IdentityElement, IdentityProofingMethod, IdentityType, PridPersistence
from eduid.userdb.logs.element import (
    ForeignIdProofingLogElement,
    MFATokenEIDASProofing,
    MFATokenProofing,
    NinProofingLogElement,
    SwedenConnectEIDASProofing,
    SwedenConnectProofing,
)
from eduid.userdb.proofing import NinProofingElement, ProofingUser
from eduid.userdb.proofing.state import NinProofingState
from eduid.webapp.common.api.helpers import set_user_names_from_foreign_id, verify_nin_for_user
from eduid.webapp.common.api.messages import CommonMsg
from eduid.webapp.common.proofing.base import (
    GenericResult,
    MatchResult,
    MfaData,
    ProofingElementResult,
    ProofingFunctions,
    VerifyCredentialResult,
    VerifyUserResult,
)
from eduid.webapp.common.proofing.methods import ProofingMethod
from eduid.webapp.eidas.app import current_eidas_app as current_app
from eduid.webapp.eidas.helpers import EidasMsg
from eduid.webapp.eidas.saml_session_info import BaseSessionInfo, ForeignEidSessionInfo, NinSessionInfo


@dataclass
class SwedenConnectProofingFunctions[BaseSessionInfoVar: BaseSessionInfo](ProofingFunctions[BaseSessionInfoVar]):
    def get_mfa_data(self) -> GenericResult[MfaData]:
        return GenericResult(
            result=MfaData(
                issuer=self.session_info.issuer,
                authn_instant=self.session_info.authn_instant.isoformat(),
                authn_context=self.session_info.authn_context,
            )
        )

    def get_current_loa(self) -> GenericResult[str | None]:
        if self.session_info.authn_context is None:
            return GenericResult(result=None)
        current_loa = current_app.conf.authn_context_loa_map.get(self.session_info.authn_context)
        return GenericResult(result=current_loa)

    def get_identity(self, user: User) -> IdentityElement | None:
        raise NotImplementedError("Subclass must implement get_identity")

    def verify_identity(self, user: User) -> VerifyUserResult:
        raise NotImplementedError("Subclass must implement verify_identity")

    def match_identity(self, user: User, proofing_method: ProofingMethod) -> MatchResult:
        raise NotImplementedError("Subclass must implement match_identity")

    def credential_proofing_element(self, user: User, credential: Credential) -> ProofingElementResult:
        raise NotImplementedError("Subclass must implement credential_proofing_element")

    def mark_credential_as_verified(self, credential: Credential, loa: str | None) -> VerifyCredentialResult:
        raise NotImplementedError("Subclass must implement mark_credential_as_verified")


@dataclass
class FrejaProofingFunctions(SwedenConnectProofingFunctions[NinSessionInfo]):
    def get_identity(self, user: User) -> IdentityElement | None:
        return user.identities.nin

    def verify_identity(self, user: User) -> VerifyUserResult:
        proofing_user = ProofingUser.from_user(user, current_app.private_userdb)

        # Create a proofing log
        proofing_log_entry = self.identity_proofing_element(user=user)
        if proofing_log_entry.error:
            return VerifyUserResult(error=proofing_log_entry.error)
        assert isinstance(proofing_log_entry.data, NinProofingLogElement)  # please type checking

        # Verify NIN for user
        date_of_birth = self.session_info.attributes.date_of_birth
        nin_element = NinProofingElement(
            number=self.session_info.attributes.nin,
            date_of_birth=datetime(year=date_of_birth.year, month=date_of_birth.month, day=date_of_birth.day),
            created_by=current_app.conf.app_name,
            is_verified=False,
        )
        proofing_state = NinProofingState(id=None, modified_ts=None, eppn=proofing_user.eppn, nin=nin_element)
        try:
            if not verify_nin_for_user(proofing_user, proofing_state, proofing_log_entry.data):
                current_app.logger.error(f"Failed verifying NIN for user {proofing_user}")
                return VerifyUserResult(error=CommonMsg.temp_problem)
        except AmTaskFailed:
            current_app.logger.exception("Verifying NIN for user failed")
            return VerifyUserResult(error=CommonMsg.temp_problem)
        except LockedIdentityViolation:
            current_app.logger.exception("Verifying NIN for user failed")
            return VerifyUserResult(error=CommonMsg.locked_identity_not_matching)

        current_app.stats.count(name="nin_verified")
        # re-load the user from central db before returning
        _user = current_app.central_userdb.get_user_by_eppn(proofing_user.eppn)
        return VerifyUserResult(user=ProofingUser.from_user(_user, current_app.private_userdb))

    def identity_proofing_element(self, user: User) -> ProofingElementResult:
        issuer: str | None
        authn_context: str | None

        if self.backdoor:
            proofing_version = "1999v1"
            issuer = "MAGIC COOKIE"
            authn_context = "MAGIC COOKIE"
        else:
            proofing_version = self.config.freja_proofing_version
            issuer = self.session_info.issuer
            authn_context = self.session_info.authn_context

        _nin = self.session_info.attributes.nin

        data = SwedenConnectProofing(
            authn_context_class=authn_context,
            created_by=current_app.conf.app_name,
            eppn=user.eppn,
            issuer=issuer,
            nin=_nin,
            given_name=self.session_info.attributes.given_name,
            surname=self.session_info.attributes.surname,
            proofing_version=proofing_version,
        )
        return ProofingElementResult(data=data)

    def credential_proofing_element(self, user: User, credential: Credential) -> ProofingElementResult:
        issuer: str | None
        authn_context: str | None

        if self.backdoor:
            proofing_version = "1999v1"
            issuer = "MAGIC COOKIE"
            authn_context = "MAGIC COOKIE"
        else:
            proofing_version = self.config.security_key_proofing_version
            issuer = self.session_info.issuer
            authn_context = self.session_info.authn_context

        # please type checking
        assert user.identities.nin

        data = MFATokenProofing(
            authn_context_class=authn_context,
            created_by=self.app_name,
            eppn=user.eppn,
            issuer=issuer,
            key_id=credential.key,
            nin=user.identities.nin.number,
            given_name=self.session_info.attributes.given_name,
            surname=self.session_info.attributes.surname,
            proofing_version=proofing_version,
        )
        return ProofingElementResult(data=data)

    def match_identity(self, user: User, proofing_method: ProofingMethod) -> MatchResult:
        identity_type = IdentityType.NIN
        asserted_unique_value = self.session_info.attributes.nin
        return self._match_identity_for_mfa(
            user=user,
            identity_type=identity_type,
            asserted_unique_value=asserted_unique_value,
            proofing_method=proofing_method,
        )

    def mark_credential_as_verified(self, credential: Credential, loa: str | None) -> VerifyCredentialResult:
        if loa != "loa3":
            return VerifyCredentialResult(error=EidasMsg.authn_context_mismatch)

        credential.is_verified = True
        credential.proofing_method = self.config.security_key_proofing_method
        credential.proofing_version = self.config.security_key_proofing_version

        return VerifyCredentialResult(credential=credential)


@dataclass()
class EidasProofingFunctions(SwedenConnectProofingFunctions[ForeignEidSessionInfo]):
    def get_identity(self, user: User) -> IdentityElement | None:
        return user.identities.eidas

    def verify_identity(self, user: User) -> VerifyUserResult:
        proofing_user = ProofingUser.from_user(user, current_app.private_userdb)

        existing_identity = user.identities.eidas
        locked_identity = user.locked_identity.eidas

        acc_loa = self.get_current_loa()
        if acc_loa is None or acc_loa.result is None:
            return VerifyUserResult(error=EidasMsg.authn_context_mismatch)

        loa = EIDASLoa(acc_loa.result)
        date_of_birth = self.session_info.attributes.date_of_birth
        new_identity = EIDASIdentity(
            created_by=current_app.conf.app_name,
            prid=self.session_info.attributes.prid,
            prid_persistence=self.session_info.attributes.prid_persistence,
            loa=loa,
            date_of_birth=datetime(year=date_of_birth.year, month=date_of_birth.month, day=date_of_birth.day),
            country_code=self.session_info.attributes.country_code,
            verified_by=current_app.conf.app_name,
            is_verified=True,
            proofing_method=IdentityProofingMethod.SWEDEN_CONNECT,
            proofing_version=self.config.foreign_eid_proofing_version,
        )

        # check if the just verified identity matches the locked identity
        if locked_identity is not None and locked_identity.prid != new_identity.prid:
            if not self._can_replace_identity(proofing_user=proofing_user):
                # asserted identity did not match the locked identity
                return VerifyUserResult(error=CommonMsg.locked_identity_not_matching)
            # replace the locked identity as the users asserted prid has changed,
            # and we are sure enough that it is the same person
            proofing_user.replace_locked = new_identity.identity_type

        # the existing identity is not verified, just remove it
        if existing_identity is not None:
            proofing_user.identities.remove(key=ElementKey(IdentityType.EIDAS))

        # everything seems to check out, add the new identity to the user
        proofing_user.identities.add(element=new_identity)

        # Create a proofing log
        proofing_log_entry = self.identity_proofing_element(user=proofing_user)
        if proofing_log_entry.error:
            return VerifyUserResult(error=proofing_log_entry.error)
        assert isinstance(proofing_log_entry.data, ForeignIdProofingLogElement)  # please type checking

        # update the users names from the verified identity
        proofing_user = set_user_names_from_foreign_id(proofing_user, proofing_log_entry.data)

        # Verify EIDAS identity for user
        if not current_app.proofing_log.save(proofing_log_entry.data):
            current_app.logger.error("Failed to save EIDAS identity proofing log for user")
            return VerifyUserResult(error=CommonMsg.temp_problem)
        try:
            # Save user to private db
            current_app.private_userdb.save(proofing_user)
            # Ask am to sync user to central db
            current_app.logger.info("Request sync for user")
            result = current_app.am_relay.request_user_sync(proofing_user)
            current_app.logger.info(f"Sync result for user: {result}")
        except AmTaskFailed:
            current_app.logger.exception("Verifying EIDAS identity for user failed")
            return VerifyUserResult(error=CommonMsg.temp_problem)

        current_app.stats.count(name="eidas_verified")
        # load the user from central db before returning
        _user = current_app.central_userdb.get_user_by_eppn(proofing_user.eppn)
        return VerifyUserResult(user=_user)

    def identity_proofing_element(self, user: User) -> ProofingElementResult:
        data = SwedenConnectEIDASProofing(
            authn_context_class=self.session_info.authn_context,
            country_code=self.session_info.attributes.country_code,
            created_by=current_app.conf.app_name,
            date_of_birth=self.session_info.attributes.date_of_birth.strftime("%Y-%m-%d"),
            eidas_person_identifier=self.session_info.attributes.eidas_person_identifier,
            eppn=user.eppn,
            given_name=self.session_info.attributes.given_name,
            issuer=self.session_info.issuer,
            prid=self.session_info.attributes.prid,
            prid_persistence=self.session_info.attributes.prid_persistence,
            proofing_version=current_app.conf.foreign_eid_proofing_version,
            surname=self.session_info.attributes.surname,
            transaction_identifier=self.session_info.attributes.transaction_identifier,
        )
        return ProofingElementResult(data=data)

    def credential_proofing_element(self, user: User, credential: Credential) -> ProofingElementResult:
        data = MFATokenEIDASProofing(
            authn_context_class=self.session_info.authn_context,
            country_code=self.session_info.attributes.country_code,
            created_by=current_app.conf.app_name,
            date_of_birth=self.session_info.attributes.date_of_birth.strftime("%Y-%m-%d"),
            eidas_person_identifier=self.session_info.attributes.eidas_person_identifier,
            eppn=user.eppn,
            given_name=self.session_info.attributes.given_name,
            issuer=self.session_info.issuer,
            key_id=credential.key,  # DIFF
            prid=self.session_info.attributes.prid,
            prid_persistence=self.session_info.attributes.prid_persistence,
            proofing_version=current_app.conf.security_key_foreign_eid_proofing_version,  # DIFF
            surname=self.session_info.attributes.surname,
            transaction_identifier=self.session_info.attributes.transaction_identifier,
        )
        return ProofingElementResult(data=data)

    def match_identity(self, user: User, proofing_method: ProofingMethod) -> MatchResult:
        identity_type = IdentityType.EIDAS
        asserted_unique_value = self.session_info.attributes.prid
        return self._match_identity_for_mfa(
            user=user,
            identity_type=identity_type,
            asserted_unique_value=asserted_unique_value,
            proofing_method=proofing_method,
        )

    def _can_replace_identity(self, proofing_user: ProofingUser) -> bool:
        locked_identity = proofing_user.locked_identity.eidas
        if locked_identity is None:
            return True
        if locked_identity.prid_persistence is PridPersistence.A:
            # identity is persistent and can not be replaced
            return False
        # the locked identity for this account has prid persistence B or C these change over time.
        # try to verify that it is the same person with a new eid
        date_of_birth_matches = locked_identity.date_of_birth.date() == self.session_info.attributes.date_of_birth
        given_name_matches = proofing_user.given_name == self.session_info.attributes.given_name
        surname_matches = proofing_user.surname == self.session_info.attributes.surname
        if date_of_birth_matches and given_name_matches and surname_matches:
            return True
        return False

    def mark_credential_as_verified(self, credential: Credential, loa: str | None) -> VerifyCredentialResult:
        if loa not in ["eidas-nf-low", "eidas-nf-sub", "eidas-nf-high"]:
            return VerifyCredentialResult(error=EidasMsg.authn_context_mismatch)

        credential.is_verified = True
        credential.proofing_method = self.config.security_key_proofing_method
        credential.proofing_version = self.config.security_key_foreign_eid_proofing_version

        return VerifyCredentialResult(credential=credential)


def get_proofing_functions(
    session_info: BaseSessionInfo,
    app_name: str,
    config: ProofingConfigMixin,
    backdoor: bool,
) -> ProofingFunctions:
    if isinstance(session_info, NinSessionInfo):
        return FrejaProofingFunctions(session_info=session_info, app_name=app_name, config=config, backdoor=backdoor)
    elif isinstance(session_info, ForeignEidSessionInfo):
        return EidasProofingFunctions(session_info=session_info, app_name=app_name, config=config, backdoor=backdoor)
    else:
        raise NotImplementedError(f"MFA matching for {type(session_info)} not implemented")
