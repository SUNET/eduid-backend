from dataclasses import dataclass
from datetime import datetime

from iso3166 import countries
from pymongo.errors import PyMongoError

from eduid.common.config.base import ProofingConfigMixin
from eduid.common.rpc.exceptions import AmTaskFailed
from eduid.userdb import User
from eduid.userdb.credentials import Credential
from eduid.userdb.element import ElementKey
from eduid.userdb.exceptions import LockedIdentityViolation
from eduid.userdb.identity import (
    FrejaIdentity,
    FrejaRegistrationLevel,
    IdentityElement,
    IdentityProofingMethod,
    IdentityType,
)
from eduid.userdb.logs.element import (
    FrejaEIDForeignProofing,
    FrejaEIDNINProofing,
    MFATokenFrejaEIDForeignProofing,
    MFATokenFrejaEIDProofing,
    NinProofingLogElement,
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
from eduid.webapp.freja_eid.app import current_freja_eid_app as current_app
from eduid.webapp.freja_eid.helpers import FrejaEIDDocumentUserInfo, FrejaEIDMsg

__author__ = "lundberg"


@dataclass
class FrejaEIDProofingFunctions(ProofingFunctions[FrejaEIDDocumentUserInfo]):
    def is_swedish_document(self) -> bool:
        issuing_country = countries.get(self.session_info.document.country, None)
        sweden = countries.get("SE")
        if not sweden:
            raise RuntimeError('Could not find country "SE" in iso3166')
        if not issuing_country:
            raise RuntimeError(f'Could not find country "{self.session_info.document.country}" in iso3166')
        return issuing_country == sweden

    def get_current_loa(self) -> GenericResult[str | None]:
        current_loa = f"freja-{self.session_info.loa_level.lower()}"
        return GenericResult(result=current_loa)

    def get_mfa_data(self) -> GenericResult[MfaData]:
        current_loa = self.get_current_loa()
        if current_loa.error:
            return GenericResult(error=current_loa.error)

        return GenericResult(
            result=MfaData(
                issuer=self.session_info.iss,
                authn_instant=datetime.fromtimestamp(self.session_info.iat).isoformat(),
                authn_context=current_loa.result,
            )
        )

    def get_identity(self, user: User) -> IdentityElement | None:
        if self.is_swedish_document():
            return user.identities.nin
        return user.identities.freja

    def verify_identity(self, user: User) -> VerifyUserResult:
        if self.is_swedish_document():
            return self._verify_nin_identity(user)
        return self._verify_foreign_identity(user)

    def _verify_nin_identity(self, user: User) -> VerifyUserResult:
        proofing_user = ProofingUser.from_user(user, current_app.private_userdb)

        # force user to be registered with PLUS registration level for a NIN identity
        if self.session_info.registration_level != FrejaRegistrationLevel.PLUS:
            return VerifyUserResult(error=FrejaEIDMsg.registration_level_not_satisfied)

        # Create a proofing log
        proofing_log_entry = self.identity_proofing_element(user=user)
        if proofing_log_entry.error:
            return VerifyUserResult(error=proofing_log_entry.error)
        assert isinstance(proofing_log_entry.data, NinProofingLogElement)  # please type checking

        # Verify NIN for user
        date_of_birth = self.session_info.date_of_birth
        try:
            nin_element = NinProofingElement(
                number=self.session_info.personal_identity_number,
                date_of_birth=datetime(year=date_of_birth.year, month=date_of_birth.month, day=date_of_birth.day),
                created_by=current_app.conf.app_name,
                is_verified=False,
            )
            proofing_state = NinProofingState(id=None, modified_ts=None, eppn=proofing_user.eppn, nin=nin_element)
            if not verify_nin_for_user(proofing_user, proofing_state, proofing_log_entry.data):
                current_app.logger.error(f"Failed verifying NIN for user {proofing_user}")
                return VerifyUserResult(error=CommonMsg.temp_problem)
        except (AmTaskFailed, PyMongoError):
            current_app.logger.exception("Verifying NIN for user failed")
            return VerifyUserResult(error=CommonMsg.temp_problem)
        except LockedIdentityViolation:
            current_app.logger.exception("Verifying NIN for user failed")
            return VerifyUserResult(error=CommonMsg.locked_identity_not_matching)

        current_app.stats.count(name="nin_verified")
        # re-load the user from central db before returning
        _user = current_app.central_userdb.get_user_by_eppn(proofing_user.eppn)
        return VerifyUserResult(user=ProofingUser.from_user(_user, current_app.private_userdb))

    def _verify_foreign_identity(self, user: User) -> VerifyUserResult:
        proofing_user = ProofingUser.from_user(user, current_app.private_userdb)

        # user has to be LOA3_NR for an identity
        # TODO: technically we could allow LOA2_NR but that level seems not to exist
        if self.get_current_loa().result not in current_app.conf.freja_eid_required_loa:
            return VerifyUserResult(error=FrejaEIDMsg.registration_level_not_satisfied)

        existing_identity = user.identities.freja
        locked_identity = user.locked_identity.freja

        date_of_birth = self.session_info.date_of_birth
        new_identity = FrejaIdentity(
            personal_identity_number=self.session_info.personal_identity_number,
            country_code=self.session_info.document.country,
            created_by=current_app.conf.app_name,
            date_of_birth=datetime(year=date_of_birth.year, month=date_of_birth.month, day=date_of_birth.day),
            is_verified=True,
            proofing_method=IdentityProofingMethod.FREJA_EID,
            proofing_version=current_app.conf.freja_eid_proofing_version,
            user_id=self.session_info.user_id,
            registration_level=self.session_info.registration_level,
            loa_level=self.session_info.loa_level,
            verified_by=current_app.conf.app_name,
        )

        # check if the just verified identity matches the locked identity
        if locked_identity is not None and locked_identity.user_id != new_identity.user_id:
            if not self._can_replace_identity(proofing_user=proofing_user):
                # asserted identity did not match the locked identity
                return VerifyUserResult(error=CommonMsg.locked_identity_not_matching)
            # replace the locked identity as the users asserted prid has changed,
            # and we are sure enough that it is the same person
            proofing_user.replace_locked = new_identity.identity_type

        # the existing identity is not verified, just remove it
        if existing_identity is not None:
            proofing_user.identities.remove(key=ElementKey(IdentityType.FREJA))

        # everything seems to check out, add the new identity to the user
        proofing_user.identities.add(element=new_identity)

        # Create a proofing log
        proofing_log_entry = self.identity_proofing_element(user=proofing_user)
        if proofing_log_entry.error:
            return VerifyUserResult(error=proofing_log_entry.error)
        assert isinstance(proofing_log_entry.data, FrejaEIDForeignProofing)  # please type checking

        # update the users names from the verified identity
        proofing_user = set_user_names_from_foreign_id(proofing_user, proofing_log_entry.data)

        # Verify Freja identity for user
        if not current_app.proofing_log.save(proofing_log_entry.data):
            current_app.logger.error("Failed to save Svipe identity proofing log for user")
            return VerifyUserResult(error=CommonMsg.temp_problem)
        try:
            # Save user to private db
            current_app.private_userdb.save(proofing_user)
            # Ask am to sync user to central db
            current_app.logger.info("Request sync for user")
            result = current_app.am_relay.request_user_sync(proofing_user)
            current_app.logger.info(f"Sync result for user: {result}")
        except AmTaskFailed:
            current_app.logger.exception("Verifying Svipe identity for user failed")
            return VerifyUserResult(error=CommonMsg.temp_problem)

        current_app.stats.count(name="foreign_identity_verified")
        # load the user from central db before returning
        _user = current_app.central_userdb.get_user_by_eppn(proofing_user.eppn)
        return VerifyUserResult(user=_user)

    def _can_replace_identity(self, proofing_user: ProofingUser) -> bool:
        if self.is_swedish_document():
            # TODO: Implement support for NIN identites
            return False

        locked_identity = proofing_user.locked_identity.freja
        if locked_identity is None:
            return True
        # Freja relyingPartyUserId should stay the same, but it is not impossible that it has changed
        # try to verify that it is the same person with a new Freja relyingPartyUserId
        date_of_birth_matches = locked_identity.date_of_birth.date() == self.session_info.date_of_birth
        given_name_matches = proofing_user.given_name == self.session_info.given_name
        surname_matches = proofing_user.surname == self.session_info.family_name
        return date_of_birth_matches and given_name_matches and surname_matches

    def identity_proofing_element(self, user: User) -> ProofingElementResult:
        if self.backdoor:
            # TODO: implement backdoor support?
            pass

        if self.is_swedish_document():
            return self._nin_identity_proofing_element(user)
        return self._foreign_identity_proofing_element(user)

    def credential_proofing_element(self, user: User, credential: Credential) -> ProofingElementResult:
        if self.backdoor:
            # TODO: implement backdoor support?
            pass

        if self.is_swedish_document():
            return self._nin_credential_proofing_element(user, credential)
        return self._foreign_credential_proofing_element(user, credential)

    def _nin_identity_proofing_element(self, user: User) -> ProofingElementResult:
        _nin = self.session_info.personal_identity_number
        if not _nin:
            return ProofingElementResult(error=CommonMsg.nin_invalid)

        data = FrejaEIDNINProofing(
            created_by=current_app.conf.app_name,
            eppn=user.eppn,
            nin=_nin,
            given_name=self.session_info.given_name,
            surname=self.session_info.family_name,
            user_id=self.session_info.user_id,
            transaction_id=self.session_info.transaction_id,
            document_type=self.session_info.document.type.value,  # according to Freja naming convention
            document_number=self.session_info.document.serial_number,
            proofing_version=current_app.conf.freja_eid_proofing_version,
        )
        return ProofingElementResult(data=data)

    def _foreign_identity_proofing_element(self, user: User) -> ProofingElementResult:
        # The top-level LogElement class won't allow empty strings (and not None either)
        _non_empty_identity_number = self.session_info.personal_identity_number or "freja_no_identity_number_provided"
        data = FrejaEIDForeignProofing(
            created_by=current_app.conf.app_name,
            eppn=user.eppn,
            user_id=self.session_info.user_id,
            transaction_id=self.session_info.transaction_id,
            document_type=self.session_info.document.type.value,  # according to Freja naming convention
            document_number=self.session_info.document.serial_number,
            proofing_version=current_app.conf.freja_eid_proofing_version,
            given_name=self.session_info.given_name,
            surname=self.session_info.family_name,
            date_of_birth=self.session_info.date_of_birth.isoformat(),
            country_code=self.session_info.country,
            administrative_number=_non_empty_identity_number,
            issuing_country=self.session_info.document.country,
        )
        return ProofingElementResult(data=data)

    def _nin_credential_proofing_element(self, user: User, credential: Credential) -> ProofingElementResult:
        proofing_element_result = self._nin_identity_proofing_element(user)
        assert proofing_element_result.data is not None  # please mypy
        data = MFATokenFrejaEIDProofing(**proofing_element_result.data.to_dict(), key_id=credential.key)
        return ProofingElementResult(data=data)

    def _foreign_credential_proofing_element(self, user: User, credential: Credential) -> ProofingElementResult:
        proofing_element_result = self._foreign_identity_proofing_element(user)
        assert proofing_element_result.data is not None  # please mypy
        data = MFATokenFrejaEIDForeignProofing(**proofing_element_result.data.to_dict(), key_id=credential.key)
        return ProofingElementResult(data=data)

    def match_identity(self, user: User, proofing_method: ProofingMethod) -> MatchResult:
        if self.is_swedish_document():
            identity_type = IdentityType.NIN
            asserted_unique_value = self.session_info.personal_identity_number
            assert asserted_unique_value is not None  # please mypy
        else:
            identity_type = IdentityType.FREJA
            asserted_unique_value = self.session_info.user_id

        return self._match_identity_for_mfa(
            user=user,
            identity_type=identity_type,
            asserted_unique_value=asserted_unique_value,
            proofing_method=proofing_method,
        )

    def mark_credential_as_verified(self, credential: Credential, loa: str | None) -> VerifyCredentialResult:
        if loa not in self.config.freja_eid_required_loa:
            return VerifyCredentialResult(error=FrejaEIDMsg.registration_level_not_satisfied)

        credential.is_verified = True
        credential.proofing_method = self.config.security_key_proofing_method

        if not self.is_swedish_document():
            credential.proofing_version = self.config.security_key_freja_eid_proofing_version
        else:
            credential.proofing_version = self.config.security_key_foreign_freja_eid_proofing_version

        return VerifyCredentialResult(credential=credential)


def get_proofing_functions(
    session_info: FrejaEIDDocumentUserInfo,
    app_name: str,
    config: ProofingConfigMixin,
    backdoor: bool,
) -> ProofingFunctions[FrejaEIDDocumentUserInfo]:
    return FrejaEIDProofingFunctions(session_info=session_info, app_name=app_name, config=config, backdoor=backdoor)
