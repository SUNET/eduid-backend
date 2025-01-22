from abc import ABC
from dataclasses import dataclass
from typing import Generic, TypeVar

from eduid.common.config.base import ProofingConfigMixin
from eduid.common.rpc.exceptions import AmTaskFailed
from eduid.userdb import User
from eduid.userdb.credentials import Credential
from eduid.userdb.credentials.external import (
    BankIDCredential,
    EidasCredential,
    ExternalCredential,
    FrejaCredential,
    SwedenConnectCredential,
    TrustFramework,
)
from eduid.userdb.element import ElementKey
from eduid.userdb.identity import IdentityElement, IdentityType
from eduid.userdb.logs.element import ProofingLogElement
from eduid.userdb.proofing import ProofingUser
from eduid.webapp.common.api.messages import CommonMsg, TranslatableMsg
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.common.proofing.methods import (
    ProofingMethod,
    ProofingMethodBankID,
    ProofingMethodFrejaEID,
    ProofingMethodSAML,
)
from eduid.webapp.common.session import session
from eduid.webapp.eidas.app import current_eidas_app as current_app

SessionInfoVar = TypeVar("SessionInfoVar")

T = TypeVar("T")


@dataclass
class GenericResult(Generic[T]):
    result: T | None = None
    error: TranslatableMsg | None = None


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


@dataclass
class MfaData:
    issuer: str
    authn_instant: str
    authn_context: str | None


@dataclass()
class ProofingFunctions(ABC, Generic[SessionInfoVar]):
    session_info: SessionInfoVar
    app_name: str
    config: ProofingConfigMixin
    backdoor: bool

    def get_current_loa(self) -> GenericResult[str | None]:
        raise NotImplementedError("Subclass must implement get_current_loa")

    def get_mfa_data(self) -> GenericResult[MfaData]:
        raise NotImplementedError("Subclass must implement get_mfa_data")

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

    def _match_identity_for_mfa(
        self, user: User, identity_type: IdentityType, asserted_unique_value: str, proofing_method: ProofingMethod
    ) -> MatchResult:
        credential_used = None
        user_identity = user.identities.find(identity_type)
        user_locked_identity = user.locked_identity.find(identity_type)

        if user_identity and (user_identity.unique_value == asserted_unique_value and user_identity.is_verified):
            # asserted identity matched verified identity
            mfa_success = True
            current_app.logger.debug(f"Current identity {user_identity} matched asserted identity")
        elif user_locked_identity and user_locked_identity.unique_value == asserted_unique_value:
            # previously verified identity that the user just showed possession of
            mfa_success = True
            current_app.logger.debug(f"Locked identity {user_locked_identity} matched asserted identity")
            # and we can verify it again
            proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
            res = self.verify_identity(user=proofing_user)
            if res.error is not None:
                # If a message was returned, verifying the identity failed, and we abort
                return MatchResult(error=res.error)
        elif user_identity is None and user_locked_identity is None:
            # TODO: we _could_ allow the user to give consent to just adding this identity to the user here,
            #       with a request parameter passed from frontend to /mfa-authentication for example.
            mfa_success = False
            current_app.logger.debug("No identity or locked identity found for user")
        else:
            mfa_success = False
            current_app.logger.debug("No matching identity found for user")

        match proofing_method:
            case ProofingMethodSAML() | ProofingMethodBankID() | ProofingMethodFrejaEID():
                current_loa = self.get_current_loa()

                mfa_data = self.get_mfa_data()
                if mfa_data.error is not None:
                    return MatchResult(error=mfa_data.error)
                assert mfa_data.result is not None  # please mypy

                if mfa_success:
                    credential_used = self._find_or_add_credential(
                        user, proofing_method.framework, current_loa.result, proofing_method.required_loa
                    )
                    current_app.logger.debug(f"Found or added credential {credential_used}")
            case _:
                raise NotImplementedError(f"Proofing method {proofing_method} not supported")

        # OLD way - remove as soon as possible
        # update session
        session.mfa_action.success = mfa_success
        if mfa_success is True:
            # add metadata if the authentication was a success
            session.mfa_action.issuer = mfa_data.result.issuer
            session.mfa_action.authn_instant = mfa_data.result.authn_instant
            session.mfa_action.authn_context = mfa_data.result.authn_context
            session.mfa_action.credential_used = credential_used

        if not mfa_success:
            current_app.logger.error("Asserted identity not matching user verified identity")
            current_identity = self.get_identity(user)
            current_unique_value = None
            if current_identity:
                current_unique_value = current_identity.unique_value
            current_app.logger.debug(f"Current identity: {current_identity}")
            current_app.logger.debug(
                f"Current identity unique value: {current_unique_value}. Asserted unique value: {asserted_unique_value}"
            )
            current_app.logger.debug(f"Session info: {self.session_info}")

        return MatchResult(matched=mfa_success, credential_used=credential_used)

    @staticmethod
    def _find_or_add_credential(
        user: User, framework: TrustFramework | None, current_loa: str | None, required_loa: list[str]
    ) -> ElementKey | None:
        if not required_loa:
            # mainly keep mypy calm
            current_app.logger.debug("Not recording credential used without required_loa")
            return None
        if current_loa not in required_loa:
            current_app.logger.error(
                f"Can not add or find credential because current_loa {current_loa} not in required_loa {required_loa}"
            )
            return None

        cred: ExternalCredential
        this: ExternalCredential
        match framework:
            case TrustFramework.SWECONN:
                for this in user.credentials.filter(SwedenConnectCredential):
                    if this.level in required_loa:
                        current_app.logger.debug(f"Found suitable credential on user: {this}")
                        return this.key

                cred = SwedenConnectCredential(level=current_loa)
                cred.created_by = current_app.conf.app_name
                if cred.level == "loa3":
                    # TODO: proof token as SWAMID_AL3_MFA?
                    pass
            case TrustFramework.EIDAS:
                for this in user.credentials.filter(EidasCredential):
                    if this.level in required_loa:
                        current_app.logger.debug(f"Found suitable credential on user: {this}")
                        return this.key

                cred = EidasCredential(level=current_loa)
                cred.created_by = current_app.conf.app_name
            case TrustFramework.BANKID:
                for this in user.credentials.filter(BankIDCredential):
                    if this.level in required_loa:
                        current_app.logger.debug(f"Found suitable credential on user: {this}")
                        return this.key

                cred = BankIDCredential(level=current_loa)
                cred.created_by = current_app.conf.app_name
            case TrustFramework.FREJA:
                for this in user.credentials.filter(FrejaCredential):
                    if this.level in required_loa:
                        current_app.logger.debug(f"Found suitable credential on user: {this}")
                        return this.key

                cred = FrejaCredential(level=current_loa)
                cred.created_by = current_app.conf.app_name
            case _:
                current_app.logger.info(f"Not recording credential used for unknown trust framework: {framework}")
                return None

        # Reload the user from the central database, to not overwrite any earlier NIN proofings
        _user = current_app.central_userdb.get_user_by_eppn(user.eppn)
        proofing_user = ProofingUser.from_user(_user, current_app.private_userdb)

        # add cred to proofing_user
        current_app.logger.info(f"Adding new credential to proofing_user: {cred}")
        proofing_user.credentials.add(cred)

        # Save proofing_user to private db
        current_app.private_userdb.save(proofing_user)

        # Ask AM to sync proofing_user to central db
        current_app.logger.info(f"Request sync for proofing_user {proofing_user}")
        result = current_app.am_relay.request_user_sync(proofing_user)
        current_app.logger.info(f"Sync result for proofing_user {proofing_user}: {result}")

        return cred.key
