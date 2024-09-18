from abc import ABC
from dataclasses import dataclass
from typing import Generic, TypeVar

from eduid.common.config.base import ProofingConfigMixin
from eduid.common.rpc.exceptions import AmTaskFailed
from eduid.userdb import User
from eduid.userdb.credentials import Credential
from eduid.userdb.element import ElementKey
from eduid.userdb.identity import IdentityElement
from eduid.userdb.logs.element import ProofingLogElement
from eduid.userdb.proofing import ProofingUser
from eduid.webapp.common.api.messages import CommonMsg, TranslatableMsg
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.common.proofing.methods import ProofingMethod
from eduid.webapp.eidas.app import current_eidas_app as current_app

SessionInfoVar = TypeVar("SessionInfoVar")


@dataclass
class MatchResult:
    error: TranslatableMsg | None = None
    matched: bool = False
    credential_used: ElementKey | None = None


@dataclass
class VerifyUserResult:
    user: User | None = None
    error: TranslatableMsg | None = None


@dataclass
class VerifyCredentialResult(VerifyUserResult):
    credential: Credential | None = None


@dataclass
class ProofingElementResult:
    data: ProofingLogElement | None = None
    error: TranslatableMsg | None = None


@dataclass()
class ProofingFunctions(ABC, Generic[SessionInfoVar]):
    session_info: SessionInfoVar
    app_name: str
    config: ProofingConfigMixin
    backdoor: bool

    def get_identity(self, user: User) -> IdentityElement | None:
        raise NotImplementedError("Subclass must implement get_identity")

    def verify_identity(self, user: User) -> VerifyUserResult:
        raise NotImplementedError("Subclass must implement verify_identity")

    def verify_credential(self, user: User, credential: Credential, loa: str | None) -> VerifyCredentialResult:
        proofing_user = ProofingUser.from_user(user, current_app.private_userdb)

        mark_result = self.mark_credential_as_verified(credential, loa)
        if mark_result.error:
            return mark_result
        assert mark_result.credential  # please type checking
        credential = mark_result.credential

        # Create a proofing log
        proofing_log_entry = self.credential_proofing_element(user=user, credential=credential)
        if proofing_log_entry.error:
            return VerifyCredentialResult(error=proofing_log_entry.error)

        # get a reference to the credential on the proofing_user, since that is the one we'll save below
        _credential = proofing_user.credentials.find(credential.key)
        # please type checking
        assert _credential
        credential = _credential

        # Set token as verified
        credential.is_verified = True
        credential.proofing_method = self.config.security_key_proofing_method
        credential.proofing_version = self.config.security_key_proofing_version

        # Save proofing log entry and save user
        assert proofing_log_entry.data  # please type checking
        if not current_app.proofing_log.save(proofing_log_entry.data):
            current_app.logger.exception("Saving proofing log for user failed")
            return VerifyCredentialResult(error=CommonMsg.temp_problem)
        try:
            save_and_sync_user(proofing_user)
        except AmTaskFailed:
            current_app.logger.exception("Verifying token for user failed")
            return VerifyCredentialResult(error=CommonMsg.temp_problem)
        current_app.logger.info(f"Recorded credential {credential} verification in the proofing log")
        current_app.stats.count(name="fido_token_verified")

        # re-load the user from central db before returning
        _user = current_app.central_userdb.get_user_by_eppn(proofing_user.eppn)
        return VerifyCredentialResult(user=_user)

    def match_identity(self, user: User, proofing_method: ProofingMethod) -> MatchResult:
        raise NotImplementedError("Subclass must implement match_identity")

    def credential_proofing_element(self, user: User, credential: Credential) -> ProofingElementResult:
        raise NotImplementedError("Subclass must implement credential_proofing_element")

    def mark_credential_as_verified(self, credential: Credential, loa: str | None) -> VerifyCredentialResult:
        raise NotImplementedError("Subclass must implement mark_credential_as_verified")
