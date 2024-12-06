from dataclasses import dataclass

from eduid.common.config.base import ProofingConfigMixin
from eduid.common.models.saml_models import BaseSessionInfo
from eduid.common.rpc.exceptions import AmTaskFailed
from eduid.userdb import User
from eduid.userdb.credentials import Credential
from eduid.userdb.exceptions import LockedIdentityViolation
from eduid.userdb.identity import IdentityElement, IdentityType
from eduid.userdb.logs.element import BankIDProofing, MFATokenBankIDProofing, NinProofingLogElement
from eduid.userdb.proofing import NinProofingElement, ProofingUser
from eduid.userdb.proofing.state import NinProofingState
from eduid.webapp.bankid.app import current_bankid_app as current_app
from eduid.webapp.bankid.helpers import BankIDMsg
from eduid.webapp.bankid.saml_session_info import BankIDSessionInfo
from eduid.webapp.common.api.helpers import verify_nin_for_user
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


@dataclass
class BankIDProofingFunctions(ProofingFunctions[BankIDSessionInfo]):
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
        return user.identities.nin

    def verify_identity(self, user: User) -> VerifyUserResult:
        proofing_user = ProofingUser.from_user(user, current_app.private_userdb)

        # Create a proofing log
        proofing_log_entry = self.identity_proofing_element(user=user)
        if proofing_log_entry.error:
            return VerifyUserResult(error=proofing_log_entry.error)
        assert isinstance(proofing_log_entry.data, NinProofingLogElement)  # please type checking

        # Verify NIN for user
        nin_element = NinProofingElement(
            number=self.session_info.attributes.nin, created_by=current_app.conf.app_name, is_verified=False
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
        if self.backdoor:
            proofing_version = "1999v1"
        else:
            proofing_version = self.config.bankid_proofing_version

        _nin = self.session_info.attributes.nin

        data = BankIDProofing(
            created_by=current_app.conf.app_name,
            eppn=user.eppn,
            nin=_nin,
            given_name=self.session_info.attributes.given_name,
            surname=self.session_info.attributes.surname,
            proofing_version=proofing_version,
            transaction_id=self.session_info.attributes.transaction_id,
        )
        return ProofingElementResult(data=data)

    def credential_proofing_element(self, user: User, credential: Credential) -> ProofingElementResult:
        if self.backdoor:
            proofing_version = "1999v1"
        else:
            proofing_version = self.config.security_key_proofing_version

        # please type checking
        assert user.identities.nin

        data = MFATokenBankIDProofing(
            created_by=self.app_name,
            eppn=user.eppn,
            key_id=credential.key,
            nin=user.identities.nin.number,
            given_name=self.session_info.attributes.given_name,
            surname=self.session_info.attributes.surname,
            proofing_version=proofing_version,
            transaction_id=self.session_info.attributes.transaction_id,
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
        if loa != "uncertified-loa3":
            return VerifyCredentialResult(error=BankIDMsg.authn_context_mismatch)

        credential.is_verified = True
        credential.proofing_method = self.config.security_key_proofing_method
        credential.proofing_version = self.config.security_key_proofing_version

        return VerifyCredentialResult(credential=credential)


def get_proofing_functions(
    session_info: BaseSessionInfo,
    app_name: str,
    config: ProofingConfigMixin,
    backdoor: bool,
) -> ProofingFunctions:
    if isinstance(session_info, BankIDSessionInfo):
        return BankIDProofingFunctions(session_info=session_info, app_name=app_name, config=config, backdoor=backdoor)
    else:
        raise NotImplementedError(f"Proofing functions for {type(session_info)} not implemented")
